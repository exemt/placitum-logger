package query

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeCountry(t *testing.T) {
	if got := Normalize(Filter{Country: " DE "}).Country; got != "de" {
		t.Fatalf("case: %q", got)
	}

	for _, raw := range []string{"d", "deu", "d1", "р у", "de'--"} {
		if got := normalizeCountry(raw); got != "" {
			t.Fatalf("junk %q survived as %q", raw, got)
		}
	}
}

// Страна и ASN спрашиваются словарём, значение уезжает привязкой: в тексте
// запроса его быть не должно.
func TestBuildGeoPlaceholders(t *testing.T) {
	sql, args := build(Normalize(Filter{
		Country: "DE",
		ASN:     9009,
		From:    time.Unix(0, 0).UTC(),
		To:      time.Unix(1, 0).UTC(),
	}))

	if strings.Contains(sql, "'de'") || strings.Contains(sql, "9009") {
		t.Fatalf("geo leaked into SQL: %s", sql)
	}

	if !strings.Contains(sql, CountryExpr+" = @country") ||
		!strings.Contains(sql, ASNExpr+" = @asn") {
		t.Fatalf("geo clauses: %s", sql)
	}

	if len(args) < 4 {
		t.Fatalf("args: %d", len(args))
	}
}

// Ноль и пустая строка -- «не спрашивали»: словарь в запросе не появляется,
// иначе обычный список платил бы за гео на каждой странице.
func TestBuildSkipsGeoWhenEmpty(t *testing.T) {
	sql, _ := build(Normalize(Filter{
		From: time.Unix(0, 0).UTC(),
		To:   time.Unix(1, 0).UTC(),
	}))

	if strings.Contains(sql, "dictGet") {
		t.Fatalf("dictionary touched without filter: %s", sql)
	}
}

func TestGroupByGeo(t *testing.T) {
	by := ParseGroupBy("country,asn")
	if len(by) != 2 || by[0] != "country" || by[1] != "asn" {
		t.Fatalf("axes: %#v", by)
	}

	sql, _ := buildGroups(Normalize(Filter{
		From:  time.Unix(0, 0).UTC(),
		To:    time.Unix(1, 0).UTC(),
		Limit: 10,
	}), by, ParseGroupSort(by, "", ""))

	if !strings.Contains(sql, CountryExpr+" AS country") ||
		!strings.Contains(sql, ASNExpr+" AS asn") {
		t.Fatalf("geo axes: %s", sql)
	}

	// Группировка и сортировка ссылаются на псевдоним, а не на выражение
	// целиком: иначе dictGet считался бы дважды.
	if !strings.Contains(sql, "GROUP BY country, asn") {
		t.Fatalf("group by: %s", sql)
	}
}
