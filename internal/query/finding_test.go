package query

import (
	"strings"
	"testing"
	"time"
)

// Правило и код приезжают из строки запроса: в SQL они попадают только
// привязкой, иначе поиск по находкам стал бы точкой инъекции.
func TestBuildFindingsUsesPlaceholders(t *testing.T) {
	sql, args := buildFindings(NormalizeFinding(FindingFilter{
		Rule:      "913100",
		Code:      "crs-913100",
		Profile:   "strict",
		Inspector: "modsec",
		Severity:  "critical",
		From:      time.Unix(0, 0).UTC(),
		To:        time.Unix(1, 0).UTC(),
		Limit:     10,
	}))

	for _, leak := range []string{"913100", "strict", "modsec", "critical"} {
		if strings.Contains(sql, leak) {
			t.Fatalf("value leaked into SQL: %s", sql)
		}
	}

	for _, clause := range []string{
		"rule = @rule", "code = @code", "profile = @profile",
		"inspector = @inspector", "severity = @severity",
	} {
		if !strings.Contains(sql, clause) {
			t.Fatalf("missing %q: %s", clause, sql)
		}
	}

	if len(args) < 8 {
		t.Fatalf("args: %d", len(args))
	}
}

/*
 * Счёт -- с FINAL: до слияния повторно доставленная находка лежит дважды, и
 * счёт читает всё окно. Список -- без него и в порядке ключа задом наперёд,
 * чтобы ClickHouse шёл с хвоста и останавливался на LIMIT; дубль на странице
 * снимает scanFindings.
 */
func TestFindingCountIsFinalListIsOrdered(t *testing.T) {
	list, _ := buildFindings(NormalizeFinding(FindingFilter{Rule: "913100"}))
	count, _ := buildFindingCount(NormalizeFinding(FindingFilter{Rule: "913100"}))

	if !strings.Contains(count, "waf.audit_finding FINAL") {
		t.Fatalf("count must use FINAL: %s", count)
	}

	if strings.Contains(list, "FINAL") ||
		!strings.Contains(list, "ORDER BY ts DESC, node DESC, ray DESC, phase DESC,"+
			" inspector DESC, finding_idx DESC, frame_direction DESC, frame_seq DESC LIMIT") {
		t.Fatalf("list: %s", list)
	}
}

func TestNormalizeFinding(t *testing.T) {
	f := NormalizeFinding(FindingFilter{Severity: "urgent", Verdict: "drop", Limit: 5000})

	if f.Severity != "" || f.Verdict != "" || f.Limit != 200 {
		t.Fatalf("got %+v", f)
	}

	// Окно по умолчанию — сутки, как и у позвоночника.
	if f.From.IsZero() || f.To.IsZero() {
		t.Fatalf("window: %+v", f)
	}
}

// Точечный поиск по ray окном не сужается: по ссылке из тикета открывают
// вчерашний инцидент.
func TestBuildFindingsRayIgnoresWindow(t *testing.T) {
	sql, _ := buildFindings(NormalizeFinding(FindingFilter{
		Ray:  "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
		Node: "edge-01",
	}))

	if !strings.Contains(sql, "ray = @ray") || !strings.Contains(sql, "node = @node") {
		t.Fatalf("ray lookup: %s", sql)
	}

	if strings.Contains(sql, "ts >= @from") {
		t.Fatalf("ray lookup must not be windowed: %s", sql)
	}
}
