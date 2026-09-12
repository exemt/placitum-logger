/*
 * Чтение объектов архива по локатору из записи аудита.
 *
 * Это не горячий путь и не инспекция. Сюда приходят, когда человек открыл
 * карточку инцидента и хочет увидеть то, чего в позвоночнике нет и быть не
 * может: сырые заголовки, строку запроса, тело. В записи лежит только локатор —
 * содержимое достаётся отсюда.
 *
 * Слой ровно один — архив. Горячий обменник (Redis) сюда не ходит и ходить не
 * может: он внутренний контур волны, живёт секунды и до читателя записи не
 * доживает никогда. Всё, чего маршрут не назвал в waf_archive, модуль
 * удаляет сразу после вердикта; всё, что назвал, забирает агент — и публикует
 * запись, уже подменив адресацию архивной. Агент чистит обменник последним шагом,
 * после публикации, поэтому и промежуточного состояния «запись есть, ключ ещё
 * жив» в записи не видно: адресация в ней либо архивная, либо отсутствует.
 * См. nginx/agent/internal/retain/retain.go и docs/body-storage.md.
 *
 * «Содержимого нет» — законный ответ, а не отказ. Причин у него больше
 * десятка, и все они разные для того, кто разбирает инцидент: тело не
 * сохраняли, тело удалили сразу после вердикта, объект не дожил до читателя,
 * архив поиску не открыт. Поэтому Fetch возвращает причину в результате, а
 * ошибкой — только то, что должен чинить оператор.
 */

package store

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ErrGone — объекта по адресу уже нет. Не отказ: у бакета есть lifecycle.
var ErrGone = errors.New("store: object is gone")

// Причины отсутствия содержимого, которые называет сам поиск. Всё остальное
// приезжает готовым в locator.unavailable — там причины модуля (oversize,
// store_error, streaming_not_supported) и агента (expired, empty, overload,
// archive_error).
const (
	// Объект не сохраняли вовсе: маршрут его не снимает, класть было нечего
	// либо волна обменника не открывала.
	ReasonAbsent = "absent"

	// Локатор есть, адресации в нём нет: объект не пережил вердикт. Так
	// выглядит всё, чего маршрут не назвал в waf_archive, и всё, что инспектор
	// просил уровнем meta — в обменник оно не попадало вовсе.
	ReasonDiscarded = "discarded"

	// Адрес есть, срок из локатора уже прошёл: объект удалило
	// lifecycle-правило бакета, и спрашивать хранилище об этом незачем.
	ReasonTTL = "ttl_expired"

	// Адрес есть, срок не назван либо ещё не вышел, а содержимого по адресу
	// уже нет. В отличие от ttl_expired, это ответ самого хранилища.
	ReasonExpired = "expired"

	// Поиску не открыт архив этого вида. Это настройка, а не судьба объекта:
	// он может лежать на месте и ждать читателя, которому позволили прийти.
	ReasonDisabled = "store_disabled"

	// Драйвер, за которым поиск ходить не умеет. Сюда попадает и redis: если
	// горячий локатор всё-таки доехал до записи (агент не смог разобрать
	// секцию store и опубликовал её как есть), ключа за ним давно нет —
	// retain_ttl считается минутами, а карточку открывают часами позже.
	ReasonDriver = "driver_unsupported"

	// Слой ответил ошибкой. В отличие от остальных причин, эту чинят.
	ReasonError = "store_error"
)

// Content — то, что удалось поднять по локатору. Пустая Reason означает, что
// содержимое есть; непустая — что его не будет, и почему.
type Content struct {
	Reason  string
	Data    []byte
	Clipped bool
}

// Available — содержимое поднято.
func (c Content) Available() bool { return c.Reason == "" }

type Reader struct {
	cfg Config
	s3  *s3Client
}

func New(cfg Config) *Reader {
	cfg.normalize()

	r := &Reader{cfg: cfg}

	if cfg.ArchiveEnabled() {
		r.s3 = &s3Client{
			endpoint: cfg.S3.Endpoint,
			region:   cfg.S3.Region,
			access:   cfg.S3.Access,
			secret:   cfg.S3.Secret,
			http: &http.Client{
				Timeout: cfg.OpTimeout,
				Transport: &http.Transport{
					MaxIdleConnsPerHost: 4,
					IdleConnTimeout:     90 * time.Second,
				},
			},
		}
	}

	return r
}

// MaxBytes — потолок одного окна. Нужен наружу: карточка обязана сказать,
// что показанное обрезано, а не молча выдать начало за целое.
func (r *Reader) MaxBytes() int64 { return r.cfg.MaxBytes }

/*
 * Fetch поднимает один объект. Ошибка возвращается вместе с причиной, а не
 * вместо неё: карточке всё равно есть что показать — размер, контрольную сумму
 * и признаки полноты она берёт из локатора, — а оператору нужен текст того, что
 * сломалось.
 */
func (r *Reader) Fetch(ctx context.Context, kind string, loc Locator, ok bool) (Content, error) {
	return r.FetchWindow(ctx, kind, loc, ok, 0, r.cfg.MaxBytes)
}

/*
 * FetchWindow — то же, что Fetch, но окно внутри объекта. Карточка просит
 * следующее окно по scroll; limit 0 или больше потолка сжимается до MaxBytes.
 */
func (r *Reader) FetchWindow(ctx context.Context, kind string, loc Locator, ok bool, offset, limit int64) (Content, error) {
	if !ok {
		return Content{Reason: ReasonAbsent}, nil
	}

	if loc.Unavailable != "" {
		return Content{Reason: loc.Unavailable}, nil
	}

	if loc.Driver == "" || loc.Key == "" {
		return Content{Reason: ReasonDiscarded}, nil
	}

	if loc.Driver != "s3" {
		return Content{Reason: ReasonDriver}, nil
	}

	/*
	 * Срок объекта известен и вышел. Поход в хранилище дал бы тот же ответ, но
	 * на round-trip позже, и назывался бы он ошибкой чтения ровно там, где
	 * ничего не сломано.
	 *
	 * Ответ раньше самого удаления: срок в локаторе — обещание правила, а
	 * вычищает объекты сканер хранилища, и между двумя моментами объект ещё
	 * лежит. Показывать содержимое, которое исчезнет к следующему нажатию, —
	 * худшая из двух неточностей: разбор инцидента строится на том, что
	 * карточка дважды отвечает одинаково.
	 */
	if loc.Expired(time.Now()) {
		return Content{Reason: ReasonTTL}, nil
	}

	bucket := r.cfg.Bucket[kind]

	if r.s3 == nil || bucket == "" {
		return Content{Reason: ReasonDisabled}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.OpTimeout)
	defer cancel()

	if limit <= 0 || limit > r.cfg.MaxBytes {
		limit = r.cfg.MaxBytes
	}

	data, clipped, err := r.s3.get(ctx, bucket, loc.Key, offset, limit)
	if errors.Is(err, ErrGone) {
		return Content{Reason: ReasonExpired}, nil
	}
	if err != nil {
		return Content{Reason: ReasonError}, err
	}

	if loc.Size > 0 && offset+int64(len(data)) < loc.Size {
		clipped = true
	}

	return Content{Data: data, Clipped: clipped}, nil
}
