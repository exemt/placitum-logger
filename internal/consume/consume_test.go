/*
 * Разбор пачки на стороне потребителя. Свойство, которое здесь проверяется,
 * одно и главное: пачка обязана дать ровно то же, что дали бы её элементы
 * поодиночке. Иначе переезд писателей на пачки менял бы содержимое журнала,
 * а не только число сообщений.
 */

package consume

import (
	"encoding/json"
	"testing"
)

const anchor = `{
  "v": 1,
  "kind": "request",
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "nginx-1",
  "phase": "request",
  "ts": "2026-08-15T21:42:31.660Z",
  "client_ip": "203.0.113.77",
  "http": {"method": "POST", "uri": "/api/orders", "status": 403},
  "route": {"server_name": "shop.example.com", "location": "/api/"},
  "verdict": "deny"
}`

const detail = `{
  "v": 1,
  "kind": "inspector",
  "ts": "2026-08-15T21:42:31.658Z",
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "nginx-1",
  "phase": "request",
  "inspector": "modsec",
  "verdict": "score",
  "findings": [
    {"code": "crs-942100", "severity": "high", "target": "args", "rule": "942100"}
  ]
}`

func pack(t *testing.T, items ...string) []byte {
	t.Helper()

	raw := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		raw = append(raw, json.RawMessage(it))
	}

	body, err := json.Marshal(struct {
		V     int               `json:"v"`
		Kind  string            `json:"kind"`
		Items []json.RawMessage `json:"items"`
	}{V: 1, Kind: "batch", Items: raw})
	if err != nil {
		t.Fatal(err)
	}

	return body
}

func TestParseBatchMatchesSingles(t *testing.T) {
	wantRows, wantFindings, err := parse([]byte(anchor))
	if err != nil {
		t.Fatal(err)
	}

	if len(wantRows) != 1 {
		t.Fatalf("anchor gave %d rows, want 1: the fixture is wrong", len(wantRows))
	}

	_, detailFindings, err := parse([]byte(detail))
	if err != nil {
		t.Fatal(err)
	}

	if len(detailFindings) == 0 {
		t.Fatal("detail gave no findings: the fixture is wrong")
	}

	rows, findings, err := parse(pack(t, anchor, detail))
	if err != nil {
		t.Fatalf("batch parse: %v", err)
	}

	if len(rows) != len(wantRows) {
		t.Errorf("rows = %d, want %d", len(rows), len(wantRows))
	}

	if len(findings) != len(wantFindings)+len(detailFindings) {
		t.Errorf("findings = %d, want %d",
			len(findings), len(wantFindings)+len(detailFindings))
	}

	if len(rows) > 0 && rows[0].Ray != wantRows[0].Ray {
		t.Errorf("ray = %q, want %q", rows[0].Ray, wantRows[0].Ray)
	}
}

// Пачка -- транспорт, а не транзакция: битый элемент не должен уносить с собой
// остальные двести пятьдесят пять.
func TestParseBatchKeepsGoodItems(t *testing.T) {
	rows, _, err := parse(pack(t, `{"kind":"request"}`, anchor))

	if err != nil {
		t.Logf("first error reported: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("rows = %d, want the one good anchor", len(rows))
	}
}

// Пустая пачка законна и ничего не даёт: писатель мог отправить её на
// закрытии. Ошибкой это не является -- иначе сообщение вечно ездило бы на
// повтор.
func TestParseEmptyBatch(t *testing.T) {
	rows, findings, err := parse(pack(t))

	if err != nil {
		t.Fatalf("empty batch: %v", err)
	}

	if len(rows) != 0 || len(findings) != 0 {
		t.Errorf("rows/findings = %d/%d, want none", len(rows), len(findings))
	}
}
