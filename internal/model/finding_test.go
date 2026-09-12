package model

import "testing"

// Событие modsec по docs/messages/inspector-audit.schema.ts.
const detail = `{
  "v": 1,
  "kind": "inspector",
  "ts": "2026-08-15T21:42:31.658Z",
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "nginx-1",
  "phase": "request",
  "inspector": "modsec",
  "profile": "strict",
  "verdict": "score",
  "score": 50,
  "engine_ms": 1.25,
  "findings": [
    {
      "code": "crs-942100",
      "severity": "high",
      "target": "args",
      "rule": "942100",
      "offset": 12,
      "length": 8,
      "evidence": "' OR 1=1"
    },
    {
      "code": "crs-913100",
      "severity": "critical",
      "target": "header:user-agent",
      "rule": "913100",
      "confidence": 0.75
    }
  ],
  "engine": {"crs_anomaly_score": 15, "crs_threshold": 5, "crs_would_block": true}
}`

func TestFromInspectorKey(t *testing.T) {
	ev, ok, err := FromInspector([]byte(detail))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if ev.Node != "nginx-1" || ev.Ray != "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10" {
		t.Fatalf("key: %s %s", ev.Node, ev.Ray)
	}

	if ev.Phase != "request" || ev.Inspector != "modsec" {
		t.Fatalf("phase/inspector: %q %q", ev.Phase, ev.Inspector)
	}

	if len(ev.Findings) != 2 {
		t.Fatalf("findings: %d", len(ev.Findings))
	}
}

func TestFromInspectorFindings(t *testing.T) {
	ev, _, err := FromInspector([]byte(detail))
	if err != nil {
		t.Fatal(err)
	}

	first, second := ev.Findings[0], ev.Findings[1]

	if first.FindingIdx != 0 || second.FindingIdx != 1 {
		t.Fatalf("idx: %d %d", first.FindingIdx, second.FindingIdx)
	}

	if first.Rule != "942100" || first.Code != "crs-942100" || first.Severity != "high" {
		t.Fatalf("rule: %+v", first)
	}

	if first.Target != "args" || first.Offset != 12 || first.Length != 8 {
		t.Fatalf("target: %+v", first)
	}

	if first.Evidence != "' OR 1=1" {
		t.Fatalf("evidence: %q", first.Evidence)
	}

	if second.Confidence != 0.75 || second.Target != "header:user-agent" {
		t.Fatalf("second: %+v", second)
	}

	// Вердикт, счёт, профиль и время движка одни на событие: их повторяет
	// каждая строка находки, чтобы поиск по правилу не требовал JOIN.
	for _, row := range ev.Findings {
		if row.Verdict != "score" || row.Score != 50 || row.Profile != "strict" {
			t.Fatalf("event fields: %+v", row)
		}

		if row.EngineMS != 1.25 {
			t.Fatalf("engine_ms: %v", row.EngineMS)
		}

		if row.Engine == "" {
			t.Fatalf("engine must survive as raw json: %+v", row)
		}
	}

	if got := ev.Findings[0].TS.Format("2006-01-02T15:04:05.000Z"); got != "2026-08-15T21:42:31.658Z" {
		t.Fatalf("ts: %s", got)
	}
}

// Инспектор отработал и не нашёл ничего: строка всё равно нужна, иначе
// "не вызвали" и "вызвали, чисто" неразличимы.
func TestFromInspectorCleanStillWritesRow(t *testing.T) {
	ev, ok, err := FromInspector([]byte(`{
	  "kind": "inspector",
	  "ts": "2026-08-15T21:42:31.658Z",
	  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
	  "node": "nginx-1",
	  "phase": "request",
	  "inspector": "ip",
	  "profile": "default",
	  "verdict": "allow",
	  "engine_ms": 0.2,
	  "findings": [],
	  "engine": {"gen": 42}
	}`))
	if err != nil || !ok {
		t.Fatalf("from: ok=%v err=%v", ok, err)
	}

	if len(ev.Findings) != 1 {
		t.Fatalf("rows: %d", len(ev.Findings))
	}

	row := ev.Findings[0]

	if row.Code != "" || row.Rule != "" || row.FindingIdx != 0 {
		t.Fatalf("marker row must be empty on the finding side: %+v", row)
	}

	if row.Verdict != "allow" || row.Engine == "" {
		t.Fatalf("marker row keeps the verdict and the engine: %+v", row)
	}

	if row.Profile != "default" {
		t.Fatalf("marker row keeps the profile: %+v", row)
	}
}

// Смещение без длины подсвечивать нечем, поэтому не хранится вовсе.
func TestFromInspectorOffsetNeedsLength(t *testing.T) {
	ev, _, err := FromInspector([]byte(`{
	  "kind": "inspector",
	  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
	  "node": "nginx-1",
	  "inspector": "modsec",
	  "verdict": "deny",
	  "findings": [{"code": "sqli", "severity": "high", "target": "body", "offset": 7}]
	}`))
	if err != nil {
		t.Fatal(err)
	}

	if ev.Findings[0].Offset != 0 || ev.Findings[0].Length != 0 {
		t.Fatalf("offset: %+v", ev.Findings[0])
	}

	// Фазы в сообщении нет — та же подстановка, что у якоря.
	if ev.Phase != "request" {
		t.Fatalf("phase: %q", ev.Phase)
	}
}

/*
 * Событие без ray склеить не с чем: rid — слот воркера, он переиспользуется, и
 * приклеенная по нему находка попала бы к чужому запросу.
 */
func TestFromInspectorRejectsLegacyEnvelope(t *testing.T) {
	legacy := `{
	  "v": 1,
	  "kind": "inspector",
	  "ts": "2026-08-14T11:00:00.120Z",
	  "rid": "480000013b000000",
	  "node": "edge-01",
	  "phase": "request",
	  "inspector": "json",
	  "verdict": "score",
	  "score": 40,
	  "reason": {"code": "JSON_SCHEMA_MISMATCH", "rule": "POST /orders"},
	  "audit": {"mismatched": 2}
	}`

	if _, ok, err := FromInspector([]byte(legacy)); ok || err != nil {
		t.Fatalf("legacy: ok=%v err=%v", ok, err)
	}
}

func TestFromInspectorSkipsAnchor(t *testing.T) {
	_, ok, err := FromInspector([]byte(anchor))
	if err != nil || ok {
		t.Fatalf("anchor: ok=%v err=%v", ok, err)
	}
}
