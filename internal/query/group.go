/*
 * Группировка позвоночника. Тот же фильтр, что у списка, но вместо строк —
 * группы: «какие адреса долбят», «какие пути», «какими кодами» — это вопросы
 * к суткам целиком, и отвечать на них перелистыванием двухсот строк нельзя.
 *
 * Считает ClickHouse, не клиент: страница списка — срез, и группировка по
 * срезу выдавала бы топ страницы за топ окна.
 */

package query

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

/*
 * Оси группировки. Закрытый список имя → колонка: ось из строки запроса не
 * должна уметь дотянуться до произвольного выражения. `by` — кто решил
 * (verdict_by), не путать с фильтром inspector, который спрашивает «кто
 * участвовал».
 */
var groupDims = map[string]string{
	"ip":      "client_ip",
	"host":    "host",
	"uri":     "uri",
	"route":   "location_id",
	"server":  "server_name",
	"method":  "method",
	"status":  "status",
	"verdict": "verdict",
	"code":    "code",
	"by":      "verdict_by",
	"node":    "node",
	"phase":   "phase",
	/*
	 * Страна и ASN -- тоже не колонки, а словарь по каталогу (см. geo.go).
	 * Здесь псевдоним, которым на них ссылаются GROUP BY и ORDER BY.
	 */
	"country": "country",
	"asn":     "asn",
	/*
	 * Маркер -- не колонка, а разворот массива: у записи меток бывает
	 * несколько, и «каких меток сколько» -- это строка на метку. Здесь
	 * стоит псевдоним, которым на неё ссылаются GROUP BY и ORDER BY; само
	 * выражение -- в groupExprs.
	 */
	"marker": "marker",
	/*
	 * Личность -- тоже разворот массива: сессий у запроса бывает несколько
	 * (калитка контура и подсмотренная кука приложения), и запрос попадает
	 * в группу каждой. Ключ -- пара «источник:логин», не голый логин:
	 * источник входа и есть пространство имён, alice из двух разных -- два
	 * разных человека.
	 */
	"user": "session_user",
}

/*
 * Оси, которые не колонка, а выражение. Запись без меток в такой
 * группировке не участвует вовсе: arrayJoin пустого массива не даёт строк --
 * ровно то, что нужно, «сколько непомеченных» спрашивают отсутствием
 * фильтра, а не группой с пустым ключом.
 */
var groupExprs = map[string]string{
	"marker": "arrayJoin(markers)",
	/*
	 * Адрес вне каталога даёт пустой код и нулевой номер -- такие записи
	 * собираются в свою группу, а не выбрасываются: «сколько трафика мы не
	 * опознали» -- вопрос не менее законный, чем «сколько из ФРГ».
	 */
	"country": CountryExpr,
	"asn":     ASNExpr,
	/*
	 * Пара собирается на месте: отдельной колонки под неё нет -- она
	 * складывается из двух и хранить её третьей значило бы держать три
	 * копии одного факта. Запись без логина (сессия есть, имени нет)
	 * выбрасывается: группа с пустым ключом отвечала бы на вопрос
	 * «сколько неопознанных», а его задают отсутствием фильтра.
	 * arrayDistinct -- чтобы две волны одной калитки не сосчитали запрос
	 * дважды в одной и той же группе.
	 */
	"user": "arrayJoin(arrayDistinct(arrayFilter(x -> x != '', " +
		"arrayMap((s, u) -> if(u = '', '', concat(s, ':', u)), " +
		"sessions_source, sessions_user))))",
}

// groupExpr -- чем ось считается: выражение либо своя колонка.
func groupExpr(dim string) string {
	if expr, ok := groupExprs[dim]; ok {
		return expr
	}

	return groupDims[dim]
}

// Больше четырёх осей — уже не группы, а тот же список подороже.
const maxGroupBy = 4

// ParseGroupBy разбирает список осей через запятую: неизвестное и повторы
// выбрасываются, порядок сохраняется — он же порядок колонок у клиента.
func ParseGroupBy(raw string) []string {
	out := make([]string, 0, maxGroupBy)
	seen := make(map[string]struct{}, maxGroupBy)

	for _, part := range strings.Split(raw, ",") {
		dim := strings.TrimSpace(part)
		if _, ok := groupDims[dim]; !ok {
			continue
		}
		if _, dup := seen[dim]; dup {
			continue
		}
		seen[dim] = struct{}{}
		out = append(out, dim)
		if len(out) >= maxGroupBy {
			break
		}
	}

	return out
}

type Group struct {
	// Значения осей, все строками: клиент рисует ячейку, а не считает.
	Keys map[string]string `json:"keys"`
	Hits uint64            `json:"hits"`
	/*
	 * Чем группа кончилась, по вердиктам. Под фильтром «все вердикты» счёт
	 * группы сам по себе про опасность ничего не говорит: сотня запросов --
	 * это и сотня пропущенных, и сотня закрытых, и любая смесь.
	 */
	Allowed    uint64    `json:"allowed"`
	Redirected uint64    `json:"redirected"`
	Denied     uint64    `json:"denied"`
	Last       time.Time `json:"last"`
}

/*
 * Groups отдаёт страницу групп и их общее число. Число едет в той же строке
 * оконной функцией count() OVER (): группировка -- это проход по окну
 * целиком, и считать группы вторым таким же проходом значило платить за
 * окно дважды (на стенде -- половину времени ответа). Окно считается по
 * сгруппированным строкам до LIMIT, поэтому число полное, а не страницы.
 *
 * Пустая страница числа не несёт: у неё нет строк. С нулевым смещением это
 * честный ноль, со сдвигом -- вопрос к CountGroups (httpapi/audit.go).
 */
func Groups(ctx context.Context, conn driver.Conn, f Filter, by []string, sort GroupSort) ([]Group, uint64, error) {
	f = Normalize(f)
	sql, args := buildGroups(f, by, sort)

	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("groups: %w", err)
	}
	defer rows.Close()

	var (
		out   = make([]Group, 0, f.Limit)
		total uint64
	)

	for rows.Next() {
		g, n, err := scanGroup(rows, by)
		if err != nil {
			return nil, 0, err
		}

		out = append(out, g)
		total = n
	}

	return out, total, rows.Err()
}

func CountGroups(ctx context.Context, conn driver.Conn, f Filter, by []string) (uint64, error) {
	f = Normalize(f)
	sql, args := buildGroupCount(f, by)

	var n uint64
	if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("group count: %w", err)
	}

	return n, nil
}

// groupCols -- чем на оси ссылаются GROUP BY и ORDER BY: колонка либо
// псевдоним выражения, объявленный в SELECT.
func groupCols(by []string) string {
	cols := make([]string, len(by))
	for i, dim := range by {
		cols[i] = groupDims[dim]
	}

	return strings.Join(cols, ", ")
}

// groupSelect -- те же оси для SELECT: выражение с псевдонимом там, где ось
// не колонка.
func groupSelect(by []string) string {
	cols := make([]string, len(by))

	for i, dim := range by {
		if expr, ok := groupExprs[dim]; ok {
			cols[i] = expr + " AS " + groupDims[dim]
			continue
		}

		cols[i] = groupDims[dim]
	}

	return strings.Join(cols, ", ")
}

// groupExprs -- те же оси для агрегата без SELECT: псевдонима там нет.
func groupExprCols(by []string) string {
	cols := make([]string, len(by))
	for i, dim := range by {
		cols[i] = groupExpr(dim)
	}

	return strings.Join(cols, ", ")
}

// Метрики группы, по которым можно сортировать помимо осей.
var groupMetrics = map[string]string{
	"hits":   "hits",
	"denied": "denied",
	"last":   "last",
}

type GroupSort struct {
	// Ключ — имя метрики или оси; колонка SQL, не выражение из запроса.
	Key string
	Asc bool
}

/*
 * ParseGroupSort сводит сортировку к закрытому списку: метрика или одна из
 * выбранных осей. Всё прочее — топ по счёту: у групп нет «без сортировки».
 * У метрик умолчание нисходящее (сначала крупное), у осей — восходящее.
 */
func ParseGroupSort(by []string, key, dir string) GroupSort {
	metric := false
	if _, ok := groupMetrics[key]; ok {
		metric = true
	} else {
		found := false
		for _, dim := range by {
			if dim == key {
				found = true
				break
			}
		}
		if !found {
			key = "hits"
			metric = true
		}
	}

	asc := !metric
	switch dir {
	case "asc":
		asc = true
	case "desc":
		asc = false
	}

	return GroupSort{Key: key, Asc: asc}
}

func (s GroupSort) order() string {
	col := groupMetrics[s.Key]
	if col == "" {
		col = groupDims[s.Key]
	}

	dir := " DESC"
	if s.Asc {
		dir = " ASC"
	}

	// Тай-брейк по счёту: равные значения оси не должны тасоваться между
	// страницами. Сам счёт добивается временем.
	tail := ", hits DESC"
	if s.Key == "hits" {
		tail = ", last DESC"
	}

	return " ORDER BY " + col + dir + tail
}

func buildGroups(f Filter, by []string, sort GroupSort) (string, []any) {
	clauses, args := where(f)
	cols := groupCols(by)

	sql := "SELECT " + groupSelect(by) +
		", count() AS hits" +
		", countIf(verdict = 'allow') AS allowed" +
		", countIf(verdict = 'redirect') AS redirected" +
		", countIf(verdict = 'deny') AS denied" +
		", max(ts) AS last" +
		", count() OVER () AS total" +
		fromFinal + whereClause(clauses) +
		" GROUP BY " + cols +
		sort.order() + " LIMIT @limit OFFSET @offset"
	args = append(args, clickhouse.Named("limit", f.Limit), clickhouse.Named("offset", f.Offset))

	return sql, args
}

// uniqExact вместо подзапроса с GROUP BY: одно сканирование, тот же ответ.
func buildGroupCount(f Filter, by []string) (string, []any) {
	clauses, args := where(f)

	return "SELECT uniqExact(" + groupExprCols(by) + ")" + fromFinal + whereClause(clauses), args
}

/*
 * Держатели под скан — по типу колонки: адрес приходит IPv6, код — числом,
 * остальное строками. Наружу всё уходит строками, разница только в развороте.
 */
func scanGroup(rows driver.Rows, by []string) (Group, uint64, error) {
	holders := make([]any, len(by))
	for i, dim := range by {
		switch dim {
		case "ip":
			holders[i] = new(netip.Addr)
		case "status":
			holders[i] = new(uint16)
		case "asn":
			holders[i] = new(uint32)
		default:
			holders[i] = new(string)
		}
	}

	var (
		g     Group
		total uint64
	)
	dst := append(
		append([]any{}, holders...),
		&g.Hits, &g.Allowed, &g.Redirected, &g.Denied, &g.Last, &total,
	)
	if err := rows.Scan(dst...); err != nil {
		return Group{}, 0, err
	}

	g.Last = g.Last.UTC()
	g.Keys = make(map[string]string, len(by))

	for i, dim := range by {
		switch h := holders[i].(type) {
		case *netip.Addr:
			if h.IsValid() && !h.IsUnspecified() {
				g.Keys[dim] = h.Unmap().String()
			} else {
				g.Keys[dim] = ""
			}
		case *uint16:
			g.Keys[dim] = strconv.FormatUint(uint64(*h), 10)
		case *uint32:
			// Ноль -- каталог адрес не знает; пустая ячейка честнее, чем AS0.
			if *h == 0 {
				g.Keys[dim] = ""
			} else {
				g.Keys[dim] = strconv.FormatUint(uint64(*h), 10)
			}
		case *string:
			g.Keys[dim] = *h
		}
	}

	return g, total, nil
}
