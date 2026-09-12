package query

import (
	"strings"
	"testing"
	"time"
)

func TestParseGroupBy(t *testing.T) {
	got := ParseGroupBy("ip, uri, ip, bogus, host")
	if len(got) != 3 || got[0] != "ip" || got[1] != "uri" || got[2] != "host" {
		t.Fatalf("got %#v", got)
	}

	if len(ParseGroupBy("")) != 0 || len(ParseGroupBy("client_ip; DROP")) != 0 {
		t.Fatal("junk survived")
	}

	// Пятая ось отрезается: порядок сохранён, лишнее выброшено.
	got = ParseGroupBy("ip,host,uri,method,status")
	if len(got) != maxGroupBy || got[3] != "method" {
		t.Fatalf("cap: %#v", got)
	}
}

func TestParseGroupSort(t *testing.T) {
	by := []string{"ip", "uri"}

	if s := ParseGroupSort(by, "", ""); s.Key != "hits" || s.Asc {
		t.Fatalf("default: %+v", s)
	}

	// Ось сортируется, только когда выбрана; умолчание у оси — восходящее.
	if s := ParseGroupSort(by, "uri", ""); s.Key != "uri" || !s.Asc {
		t.Fatalf("dim: %+v", s)
	}
	if s := ParseGroupSort(by, "host", ""); s.Key != "hits" || s.Asc {
		t.Fatalf("unpicked dim: %+v", s)
	}
	if s := ParseGroupSort(by, "denied", "asc"); s.Key != "denied" || !s.Asc {
		t.Fatalf("dir: %+v", s)
	}
	if s := ParseGroupSort(by, "ts; DROP", ""); s.Key != "hits" {
		t.Fatalf("junk: %+v", s)
	}
}

func TestBuildGroupsUsesPlaceholders(t *testing.T) {
	sql, args := buildGroups(Normalize(Filter{
		Verdict: "deny",
		Host:    "app.example",
		From:    time.Unix(0, 0).UTC(),
		To:      time.Unix(1, 0).UTC(),
		Limit:   10,
	}), []string{"ip", "uri"}, ParseGroupSort([]string{"ip", "uri"}, "", ""))

	if strings.Contains(sql, "app.example") {
		t.Fatalf("value leaked into SQL: %s", sql)
	}

	if !strings.Contains(sql, "GROUP BY client_ip, uri") ||
		!strings.Contains(sql, "countIf(verdict = 'deny') AS denied") ||
		!strings.Contains(sql, "ORDER BY hits DESC, last DESC") ||
		!strings.Contains(sql, "LIMIT @limit OFFSET @offset") {
		t.Fatalf("sql: %s", sql)
	}

	// Число групп -- оконной функцией в той же строке, до LIMIT: второй
	// проход по окну ради счёта стоил бы столько же, сколько первый.
	if !strings.Contains(sql, ", count() OVER () AS total FROM waf.audit FINAL") {
		t.Fatalf("total: %s", sql)
	}

	if len(args) < 4 {
		t.Fatalf("args: %d", len(args))
	}

	sorted, _ := buildGroups(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}), []string{"ip", "uri"}, ParseGroupSort([]string{"ip", "uri"}, "uri", "desc"))

	if !strings.Contains(sorted, "ORDER BY uri DESC, hits DESC") {
		t.Fatalf("sorted: %s", sorted)
	}

	countSQL, _ := buildGroupCount(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}), []string{"by", "status"})

	if !strings.Contains(countSQL, "uniqExact(verdict_by, status)") ||
		strings.Contains(countSQL, "LIMIT") {
		t.Fatalf("count: %s", countSQL)
	}
}

/*
 * Маркер -- ось-выражение: в SELECT разворот массива с псевдонимом, в GROUP BY
 * и ORDER BY -- псевдоним, в агрегате счёта -- само выражение. Ошибка здесь
 * даёт не пустой ответ, а SQL, который ClickHouse не разберёт.
 */
func TestBuildGroupsMarkerUnrollsArray(t *testing.T) {
	by := []string{"marker"}

	sql, _ := buildGroups(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}), by, ParseGroupSort(by, "marker", ""))

	if !strings.Contains(sql, "SELECT arrayJoin(markers) AS marker,") ||
		!strings.Contains(sql, "GROUP BY marker") ||
		!strings.Contains(sql, "ORDER BY marker ASC, hits DESC") {
		t.Fatalf("sql: %s", sql)
	}

	countSQL, _ := buildGroupCount(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}), by)

	if !strings.Contains(countSQL, "uniqExact(arrayJoin(markers))") {
		t.Fatalf("count: %s", countSQL)
	}
}

// Фильтр по метке -- has() по массиву, значение плейсхолдером.
func TestWhereMarker(t *testing.T) {
	sql, _ := build(Normalize(Filter{
		Marker: "bot-farm",
		From:   time.Unix(0, 0).UTC(),
		To:     time.Unix(1, 0).UTC(),
	}))

	if !strings.Contains(sql, "has(markers, @marker)") ||
		strings.Contains(sql, "bot-farm") {
		t.Fatalf("sql: %s", sql)
	}
}

/*
 * Личность -- ось-выражение поверх двух массивов: ключ группы это пара
 * «источник:логин», а не голый логин. Сессия без имени в группировку не
 * попадает, повтор одной пары в записи не считается дважды.
 */
func TestBuildGroupsUserPairsSourceAndLogin(t *testing.T) {
	by := []string{"user"}

	sql, _ := buildGroups(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}), by, ParseGroupSort(by, "user", ""))

	if !strings.Contains(sql, "concat(s, ':', u)") ||
		!strings.Contains(sql, "arrayFilter(x -> x != ''") ||
		!strings.Contains(sql, "arrayDistinct(") ||
		!strings.Contains(sql, "AS session_user,") ||
		!strings.Contains(sql, "GROUP BY session_user") ||
		!strings.Contains(sql, "ORDER BY session_user ASC, hits DESC") {
		t.Fatalf("sql: %s", sql)
	}

	countSQL, _ := buildGroupCount(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}), by)

	// В агрегате -- само выражение: псевдонима без SELECT нет.
	if !strings.Contains(countSQL, "uniqExact(arrayJoin(arrayDistinct(") ||
		strings.Contains(countSQL, "uniqExact(session_user)") {
		t.Fatalf("count: %s", countSQL)
	}
}

// Ось разворачивается в фильтр той же страницы: ключ группы -- законное
// значение user=, иначе клик по группе показал бы не те строки.
func TestGroupUserKeyIsValidFilter(t *testing.T) {
	sql, _ := build(Normalize(Filter{
		User: "corp:alice",
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}))

	if !strings.Contains(sql, "arrayExists((s, u) ->") {
		t.Fatalf("drill: %s", sql)
	}
}
