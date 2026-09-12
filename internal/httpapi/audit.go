/*
 * Позвоночник и находки: список, запись, разбор записи по участникам.
 */

package httpapi

import (
	"context"
	"math"
	"net/http"

	"github.com/exemt/placitum-logger/internal/query"
)

/*
 * both гонит два запроса одного фильтра разом: страница и её счёт (группы и
 * их счёт) читают одно окно, и ждать второго после первого значит платить за
 * окно дважды подряд. Ошибка любого отменяет второго; наружу уходит первая
 * по порядку аргументов -- обе одинаково значат «ClickHouse не ответил».
 */
func both(ctx context.Context, a, b func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- b(ctx) }()

	errA := a(ctx)
	if errA != nil {
		cancel()
	}

	errB := <-done

	if errA != nil {
		return errA
	}

	return errB
}

// parseFilter — фильтр списка из строки запроса. Общий у списка и группировки:
// группы считаются по тому же окну и тем же условиям, что видны в таблице,
// иначе топ групп не сходился бы с тем, что под ним разворачивается.
func parseFilter(r *http.Request) query.Filter {
	q := r.URL.Query()
	status, hasStatus := parseStatus(q.Get("status"))

	return query.Normalize(query.Filter{
		Verdict: q.Get("verdict"),
		Code:    q.Get("code"),
		Method:  q.Get("method"),
		Host:    q.Get("host"),
		URI:     q.Get("uri"),
		// route=<uuid>[,<uuid>...]: uuid путей из waf_route_id, не имена блоков.
		LocationIDs: q["route"],
		// server=<имя>[,<имя>...]: имена блоков server {}, не Host.
		ServerNames: q["server"],
		Status:      status,
		HasStatus:   hasStatus,
		Node:        q.Get("node"),
		Ray:         q.Get("ray"),
		Phase:       q.Get("phase"),
		Inspector:   q.Get("inspector"),
		CIDRs:       q["ip"],
		// country=<две буквы>, asn=<номер>: гео адреса по каталогу, словарём
		// (см. query/geo.go). Своих колонок у них в waf.audit нет.
		Country: q.Get("country"),
		ASN:     parseASN(q.Get("asn")),
		Vars:    query.ParseVars(q["var"]),
		// user=<логин>, session=<идентификатор>: любая запись секции sessions.
		User:      q.Get("user"),
		SessionID: q.Get("session"),
		// marker=<метка>: любой элемент секции markers, строка целиком.
		Marker:  q.Get("marker"),
		Headers: query.ParsePairs(q["header"]),
		Params:  query.ParsePairs(q["param"]),
		Body:    q.Get("body"),
		Limit:   atoi(q.Get("limit")),
		Offset:  atoi(q.Get("offset")),
		From:    parseTime(q.Get("from")),
		To:      parseTime(q.Get("to")),
		// order=asc: страница с начала окна. Умолчание -- с конца, и любое
		// другое значение остаётся им же: порядок не то, о чём стоит спорить
		// с опечаткой в строке запроса.
		Asc: q.Get("order") == "asc",
	})
}

/*
 * Номер автономной системы из строки запроса. Ноль -- «не спрашивали»: в
 * каталоге ASN всегда положительный, и мусор вроде "-1" не должен превращаться
 * в четыре миллиарда обходом типа.
 */
func parseASN(raw string) uint32 {
	n := atoi(raw)
	if n <= 0 || n > math.MaxUint32 {
		return 0
	}

	return uint32(n)
}

func (a *api) list(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)

	var (
		rows  []query.Event
		total uint64
	)

	err := both(r.Context(),
		func(ctx context.Context) (err error) {
			rows, err = query.List(ctx, a.conn, f)
			return
		},
		func(ctx context.Context) (err error) {
			total, err = query.Count(ctx, a.conn, f)
			return
		})
	if err != nil {
		a.broken(w, "list", err)
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
 * groups — тот же фильтр, что у списка, но свёрнутый по осям из `by`:
 * «какие адреса долбят» отвечается группировкой окна, а не перелистыванием.
 * Пустой или сплошь неизвестный `by` — ошибка запроса: группировать не по
 * чему, и молча отдать список под видом групп было бы хуже, чем отказать.
 */
func (a *api) groups(w http.ResponseWriter, r *http.Request) {
	by := query.ParseGroupBy(r.URL.Query().Get("by"))
	if len(by) == 0 {
		fail(w, http.StatusBadRequest, "bad_group_by")
		return
	}

	sort := query.ParseGroupSort(by, r.URL.Query().Get("sort"), r.URL.Query().Get("dir"))
	f := parseFilter(r)

	// Число групп едет в той же строке, что и группы: второй проход по окну
	// ради него стоил бы столько же, сколько первый.
	rows, total, err := query.Groups(r.Context(), a.conn, f, by, sort)
	if err != nil {
		a.broken(w, "groups", err)
		return
	}

	/*
	 * Страница за краем пуста и числа не несёт, а панели оно нужно, чтобы
	 * вернуть листание на место. Только тогда -- отдельный счёт: в обычной
	 * жизни сюда не заходят.
	 */
	if len(rows) == 0 && f.Offset > 0 {
		if total, err = query.CountGroups(r.Context(), a.conn, f, by); err != nil {
			a.broken(w, "group count", err)
			return
		}
	}

	writeJSON(w, map[string]any{
		"items":  rows,
		"count":  len(rows),
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

// one — одна запись. Та же форма, что у элемента списка: карточка и строка
// списка описывают один и тот же запрос, и второй тип на то же самое клиенту
// пришлось бы разбирать дважды.
func (a *api) one(w http.ResponseWriter, r *http.Request) {
	ev, ok, err := a.record(w, r)
	if err != nil || !ok {
		return
	}

	writeJSON(w, ev)
}

/*
 * inspectors — разбор записи по участникам: кто отвечал, кто промолчал, чья
 * заявка сколько весила и что каждый нашёл. Ради этого запись и открывают.
 *
 * Пустой список участников — законный ответ: локальный бан по списку адресов
 * волны не поднимал, спрашивать было некого, и это не ошибка.
 */
func (a *api) inspectors(w http.ResponseWriter, r *http.Request) {
	ev, ok, err := a.record(w, r)
	if err != nil || !ok {
		return
	}

	findings, err := query.FindingsFor(r.Context(), a.conn, ev)
	if err != nil {
		a.broken(w, "card", err)
		return
	}

	writeJSON(w, query.CardOf(ev, findings))
}

/*
 * cardFindings — находки одного запроса плоским списком, без разбора по
 * участникам. Пустой список законен по той же причине, что и выше; отсутствие
 * самого запроса покажет соседний ресурс, поэтому 404 здесь нет.
 */
func (a *api) cardFindings(w http.ResponseWriter, r *http.Request) {
	rows, err := query.FindingsByRay(r.Context(), a.conn,
		r.PathValue("node"), r.PathValue("ray"))
	if err != nil {
		a.broken(w, "findings by ray", err)
		return
	}

	writeJSON(w, map[string]any{"items": rows, "count": len(rows)})
}

func (a *api) findings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	f := query.NormalizeFinding(query.FindingFilter{
		Node:      q.Get("node"),
		Ray:       q.Get("ray"),
		Phase:     q.Get("phase"),
		Inspector: q.Get("inspector"),
		Profile:   q.Get("profile"),
		Verdict:   q.Get("verdict"),
		Rule:      q.Get("rule"),
		Code:      q.Get("code"),
		Severity:  q.Get("severity"),
		Limit:     atoi(q.Get("limit")),
		Offset:    atoi(q.Get("offset")),
		From:      parseTime(q.Get("from")),
		To:        parseTime(q.Get("to")),
	})

	rows, err := query.ListFindings(r.Context(), a.conn, f)
	if err != nil {
		a.broken(w, "findings", err)
		return
	}

	total, err := query.CountFindings(r.Context(), a.conn, f)
	if err != nil {
		a.broken(w, "findings count", err)
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

// record — общее начало всех ручек, которые разворачивают одну запись. Ответ
// уже отправлен, если вернулось не ok: дальше вызывающему делать нечего.
func (a *api) record(w http.ResponseWriter, r *http.Request) (query.Event, bool, error) {
	// Кадр внутри соединения адресуется `frame=<direction>:<seq>`.
	ev, ok, err := query.One(r.Context(), a.conn,
		r.PathValue("node"), r.PathValue("ray"), r.URL.Query().Get("phase"),
		r.URL.Query().Get("frame"))

	if err != nil {
		a.broken(w, "get", err)
		return query.Event{}, false, err
	}

	if !ok {
		fail(w, http.StatusNotFound, "not_found")
		return query.Event{}, false, nil
	}

	return ev, true, nil
}
