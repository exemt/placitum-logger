/*
 * HTTP-поверхность поиска. Два ресурса и то, чем они разворачиваются.
 *
 * Список инцидентов узкий: по нему сканируют сутки, и всё, что нужно ровно
 * одной открытой записи, из него убрано. Разворот записи разложен по ручкам не
 * ради красоты URL, а потому что стоят они разного: разбор по инспекторам —
 * второй запрос в ClickHouse, содержимое обменника — поход в Redis или S3 за
 * объектом, которого в ClickHouse нет вовсе. Класть это в список значило бы
 * платить за всё сразу и на каждой строке.
 *
 *   GET /api/audit                              список
 *   GET /api/audit/groups?by=ip,uri             группы того же фильтра
 *   GET /api/audit/{node}/{ray}                 запись
 *   GET /api/audit/{node}/{ray}/inspectors      кто участвовал и что нашёл
 *   GET /api/audit/{node}/{ray}/findings        находки одной плоскостью
 *   GET /api/audit/{node}/{ray}/headers         сырые заголовки из обменника
 *   GET /api/audit/{node}/{ray}/args            строка запроса и её параметры
 *   GET /api/audit/{node}/{ray}/body            тело
 *
 * Окна: ?offset=&limit= — байты объекта, карточка догружает по scroll.
 *   GET /api/findings                           поиск по правилу поперёк запросов
 *
 *   GET /api/logs                               журнал процессов ноды
 *   GET /api/logs/facets                        кто и по чему писал в окно
 */

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/exemt/placitum-logger/internal/store"
)

type api struct {
	conn  driver.Conn
	store *store.Reader
	log   *slog.Logger
}

func Handler(conn driver.Conn, reader *store.Reader, log *slog.Logger) http.Handler {
	a := &api{conn: conn, store: reader, log: log}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /api/audit", a.list)

	// Группы вместо строк: тот же фильтр, свёрнутый по осям из ?by=. С
	// шаблоном {node}/{ray} не спорит — тот требует два сегмента.
	mux.HandleFunc("GET /api/audit/groups", a.groups)

	mux.HandleFunc("GET /api/audit/{node}/{ray}", a.one)

	// Разбор по инспекторам — то, ради чего запись открывают. Отдельным
	// запросом, а не полем записи: это склейка двух таблиц, и платить за неё
	// на каждой строке списка незачем.
	mux.HandleFunc("GET /api/audit/{node}/{ray}/inspectors", a.inspectors)

	// Находки того же запроса без разбора по участникам: так их забирает
	// выгрузка, которой карточка не нужна.
	mux.HandleFunc("GET /api/audit/{node}/{ray}/findings", a.cardFindings)

	// Содержимое обменника. Три вида — три ручки: у каждого своя форма разбора и
	// свой ответ на «почему пусто», а общая ручка с параметром вида ничего из
	// этого не упрощает.
	mux.HandleFunc("GET /api/audit/{node}/{ray}/headers", a.content("headers"))
	mux.HandleFunc("GET /api/audit/{node}/{ray}/args", a.content("args"))
	mux.HandleFunc("GET /api/audit/{node}/{ray}/body", a.content("body"))

	// Находки отдельным ресурсом, а не полем записи: спрашивают их иначе —
	// "где сработало правило 913100" поперёк всех запросов сразу.
	mux.HandleFunc("GET /api/findings", a.findings)

	// Журнал процессов ноды. Не аудит и не его срез: строка access_log или
	// error_log, снятая агентом с сокета, к записи запроса не привязана и
	// привязана быть не может -- в access-строке нет ray.
	mux.HandleFunc("GET /api/logs", a.logs)
	mux.HandleFunc("GET /api/logs/facets", a.logFacets)

	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	_ = enc.Encode(v)
}

// fail отвечает тем же JSON, что и успех: клиент разбирает один тип, а не два в
// зависимости от кода. Текст ошибки закрытый — подробности уходят в журнал, а
// не наружу.
func fail(w http.ResponseWriter, code int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}

func (a *api) broken(w http.ResponseWriter, what string, err error) {
	// Клиент ушёл сам: контроллер снимает запрос, когда UX бросает fetch на
	// новый клик по фильтру, и ClickHouse останавливает чтение по той же
	// отмене. Это не сбой поиска -- отвечать некому, а ERROR на каждый
	// брошенный клик врал бы в журнале.
	if errors.Is(err, context.Canceled) {
		return
	}

	a.log.Error(what, "error", err.Error())
	fail(w, http.StatusBadGateway, "query_failed")
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func parseStatus(s string) (uint16, bool) {
	if s == "" {
		return 0, false
	}

	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 999 {
		return 0, false
	}

	return uint16(n), true
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}

	return t.UTC()
}
