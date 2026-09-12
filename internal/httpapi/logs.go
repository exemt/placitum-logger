/*
 * Журнал процессов ноды: список строк и наборы значений для его фильтров.
 *
 *   GET /api/logs          строки: writer, service, severity, подстрока, окно
 *   GET /api/logs/facets   кто и по какому сервису писал в это окно
 *
 * Разворота у строки нет: она сама себе карточка. Отсюда и одна ручка вместо
 * пяти, как у аудита.
 */

package httpapi

import (
	"net/http"

	"github.com/exemt/placitum-logger/internal/query"
)

func (a *api) logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	f := query.NormalizeLog(query.LogFilter{
		Writer:   q.Get("writer"),
		Service:  q.Get("service"),
		Severity: q.Get("severity"),
		Text:     q.Get("text"),
		Limit:    atoi(q.Get("limit")),
		Offset:   atoi(q.Get("offset")),
		From:     parseTime(q.Get("from")),
		To:       parseTime(q.Get("to")),
	})

	rows, err := query.ListLogs(r.Context(), a.conn, f)
	if err != nil {
		a.broken(w, "logs", err)
		return
	}

	total, err := query.CountLogs(r.Context(), a.conn, f)
	if err != nil {
		a.broken(w, "logs count", err)
		return
	}

	writeJSON(w, map[string]any{
		"items":  rows,
		"count":  len(rows),
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

/*
 * facets — чем наполняются списки фильтров. Отдельной ручкой, а не полем
 * ответа списка: наборы меняются на порядок реже строк, и считать их на
 * каждой перелистанной странице незачем.
 */
func (a *api) logFacets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	rows, err := query.LogFacets(r.Context(), a.conn, query.LogFilter{
		From: parseTime(q.Get("from")),
		To:   parseTime(q.Get("to")),
	})
	if err != nil {
		a.broken(w, "logs facets", err)
		return
	}

	writeJSON(w, map[string]any{"items": rows, "count": len(rows)})
}
