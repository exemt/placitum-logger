/*
 * Содержимое обменника: сырые заголовки, строка запроса, тело.
 *
 * В ClickHouse этого нет и не будет — там лежат размеры и локатор. Содержимое
 * достаётся из обменника по локатору тем же кодом, каким его доставал инспектор во
 * время инспекции, и ровно тогда, когда карточку открыли.
 *
 * «Содержимого нет» — обычный ответ 200 с причиной, а не отказ. Запись
 * существует, размер и контрольная сумма верны, и единственное, чего не будет,
 * это байты; отвечать на это 404 значило бы прятать от разбирающего инцидент
 * всё остальное. Причин десяток, и они разные: тело не снимали с маршрута, его
 * удалили сразу после вердикта, ключ не дожил, архив поиску не открыт.
 */

package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/exemt/placitum-logger/internal/query"
	"github.com/exemt/placitum-logger/internal/store"
)

type pair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type content struct {
	Node  string `json:"node"`
	Ray   string `json:"ray"`
	Phase string `json:"phase"`
	Kind  string `json:"kind"`

	// Из локатора. Верно и тогда, когда содержимого уже нет: размер и хеш
	// пережили сам объект, и часто их достаточно.
	Size         int64  `json:"size"`
	DeclaredSize int64  `json:"declared_size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Complete     *bool  `json:"complete,omitempty"`
	Truncated    *bool  `json:"truncated,omitempty"`
	Encoding     string `json:"encoding,omitempty"`
	ContentType  string `json:"content_type,omitempty"`

	Store  string `json:"store,omitempty"`
	Driver string `json:"driver,omitempty"`
	Key    string `json:"key,omitempty"`

	// До какого момента объект жив в архиве. Отсутствует, когда срок неизвестен:
	// правила удаления в бакете нет, и объект переживёт саму запись.
	ExpiresAt int64 `json:"expires_at,omitempty"`

	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	// Сколько байт отдано и упёрлось ли это в потолок окна. Обрезка окном
	// и truncated локатора — разные события: второе значит, что модуль не
	// дочитал тело, первое — что за этим окном в объекте ещё есть байты.
	Offset   int64 `json:"offset"`
	Returned int   `json:"returned"`
	Clipped  bool  `json:"clipped,omitempty"`

	// Окно началось внутри значения предыдущей пары: text — продолжение,
	// а не новое имя. Карточка дописывает его к последней уже показанной паре.
	Continuation bool `json:"continuation,omitempty"`

	// Разобранное содержимое, по виду объекта.
	Headers []pair `json:"headers,omitempty"`
	Params  []pair `json:"params,omitempty"`
	Count   int    `json:"count,omitempty"`

	// Строка запроса как она пришла, до разбора на параметры: именно в этом
	// виде её видел движок правил, и именно её цитируют находки.
	Raw string `json:"raw,omitempty"`

	// Тело: текстом, если это текст, иначе base64. Признак binary нужен, чтобы
	// пустое text не путали с пустым телом.
	Text   string `json:"text,omitempty"`
	Base64 string `json:"base64,omitempty"`
	Binary bool   `json:"binary,omitempty"`
}

func (a *api) content(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ev, ok, err := a.record(w, r)
		if err != nil || !ok {
			return
		}

		out := content{
			Node:  ev.Node,
			Ray:   ev.Ray,
			Phase: ev.Phase,
			Kind:  kind,
		}

		if kind == "body" {
			out.ContentType = ev.ContentType
		}

		loc, has := locatorOf(ev, kind)

		out.Size = loc.Size
		out.DeclaredSize = loc.DeclaredSize
		out.SHA256 = loc.SHA256
		out.Complete = loc.Complete
		out.Truncated = loc.Truncated
		out.Encoding = loc.Encoding
		out.Store = loc.Store
		out.Driver = loc.Driver
		out.Key = loc.Key
		out.ExpiresAt = loc.ExpiresAt

		offset, limit := windowOf(r, a.store.MaxBytes())
		out.Offset = offset

		got, err := a.store.FetchWindow(r.Context(), kind, loc, has, offset, limit)
		if err != nil {
			// Ответ всё равно уходит: у карточки остаются размер, хеш и адрес,
			// а починить обменник читателю нечем — это забота оператора.
			a.log.Error("store fetch",
				"kind", kind, "node", ev.Node, "ray", ev.Ray,
				"driver", loc.Driver, "key", loc.Key, "error", err.Error())
		}

		out.Reason = got.Reason
		out.Available = got.Available()
		out.Returned = len(got.Data)
		out.Clipped = got.Clipped

		if out.Available {
			decode(&out, kind, got.Data, offset)
		}

		writeJSON(w, out)
	}
}

func locatorOf(ev query.Event, kind string) (store.Locator, bool) {
	if ev.Store == nil {
		return store.Locator{}, false
	}

	switch kind {
	case "headers":
		return store.ParseLocator(string(ev.Store.Headers))
	case "args":
		return store.ParseLocator(string(ev.Store.Args))
	case "body":
		return store.ParseLocator(string(ev.Store.Body))
	}

	return store.Locator{}, false
}

// defaultViewChunk — окно карточки. Без offset/limit ответ по-прежнему
// потолок обменника: старый клиент ждёт один объект, а не серию окон.
const defaultViewChunk = 32 << 10

func windowOf(r *http.Request, max int64) (offset, limit int64) {
	q := r.URL.Query()
	offset = int64(atoi(q.Get("offset")))
	if offset < 0 {
		offset = 0
	}

	if q.Get("offset") == "" && q.Get("limit") == "" {
		return 0, max
	}

	limit = int64(atoi(q.Get("limit")))
	if limit <= 0 {
		limit = defaultViewChunk
	}
	if max > 0 && limit > max {
		limit = max
	}

	return offset, limit
}

func decode(out *content, kind string, data []byte, offset int64) {
	switch kind {

	case "headers":
		pairs, cont := parseHeadersFragment(data)
		out.Headers = pairs
		out.Count = len(pairs)
		if cont != "" {
			out.Continuation = true
			out.Text = cont
		}

	case "args":
		out.Raw = string(data)
		pairs, cont := parseArgsFragment(out.Raw, offset)
		out.Params = pairs
		out.Count = len(pairs)
		if cont != "" {
			out.Continuation = true
			out.Text = cont
		}

	case "body":
		if text, n, ok := utf8Window(data); ok {
			out.Text = text
			out.Returned = n
			return
		}

		out.Binary = true
		out.Base64 = base64.StdEncoding.EncodeToString(data)
	}
}

/*
 * В обменнике заголовки лежат массивом пар: порядок получения значим, а дубликаты
 * имён (Set-Cookie, Forwarded) в объекте потерялись бы — и ровно они бывают
 * тем, из-за чего запрос отсекли. Наружу они едут парами по той же причине.
 *
 * Битый объект — пустой список, а не отказ: карточке важнее показать остальное,
 * чем упасть из-за одного нечитаемого куска.
 */
func parseHeaders(data []byte) []pair {
	var rows [][]string

	if err := json.Unmarshal(data, &rows); err != nil {
		return nil
	}

	out := make([]pair, 0, len(rows))

	for _, row := range rows {
		item := pair{}

		if len(row) > 0 {
			item.Name = row[0]
		}

		if len(row) > 1 {
			item.Value = row[1]
		}

		out = append(out, item)
	}

	return out
}

/*
 * Разбор строки запроса вручную, а не url.ParseQuery: тот складывает значения
 * в карту, теряя и порядок, и то, какой именно из двух одноимённых параметров
 * сработал. Для разбора инцидента это и есть содержательная часть — подмена
 * параметра дубликатом ровно так и выглядит.
 *
 * Неразбираемое percent-кодирование остаётся как пришло: строка запроса
 * атакующего не обязана быть корректной, и молча выбросить её значило бы
 * потерять сам признак.
 */
func parseArgs(raw string) []pair {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, "&")
	out := make([]pair, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}

		name, value, _ := strings.Cut(part, "=")

		out = append(out, pair{Name: unescape(name), Value: unescape(value)})
	}

	return out
}

func unescape(s string) string {
	out, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}

	return out
}
