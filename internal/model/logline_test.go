package model

import (
	"strings"
	"testing"
	"time"
)

func TestFromLog(t *testing.T) {
	payload := []byte(`{"v":1,"kind":"log","writer":"edge-01","lines":[
		{"ts":"2026-08-23T12:00:00.500Z","service":"nginx","severity":"error","text":"open() failed"},
		{"ts":"2026-08-23T12:00:01.000Z","service":"nginx","severity":"info","text":"GET /a 200"}
	]}`)

	rows, err := FromLog(payload)
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) != 2 {
		t.Fatalf("строк: %d", len(rows))
	}

	// Writer стоит на конверте, а в таблице обязан быть на каждой строке.
	for _, row := range rows {
		if row.Writer != "edge-01" {
			t.Fatalf("writer: %q", row.Writer)
		}
	}

	want := time.Date(2026, 8, 23, 12, 0, 0, 500_000_000, time.UTC)
	if !rows[0].TS.Equal(want) {
		t.Fatalf("ts: %v", rows[0].TS)
	}

	if rows[0].Severity != "error" || rows[0].Text != "open() failed" {
		t.Fatalf("строка: %+v", rows[0])
	}
}

// Пустой текст -- не строка: писать в журнал запись, у которой нечего читать,
// незачем.
func TestFromLogSkipsEmpty(t *testing.T) {
	rows, err := FromLog([]byte(`{"writer":"edge-01","lines":[{"ts":"","text":""}]}`))
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) != 0 {
		t.Fatalf("строк: %d", len(rows))
	}
}

// Пачка без имени ноды: строку всё равно кладём, но подписанной так, чтобы её
// было видно в фильтре, а не потерянной среди чужих.
func TestFromLogUnknownWriter(t *testing.T) {
	rows, err := FromLog([]byte(`{"lines":[{"text":"line"}]}`))
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) != 1 || rows[0].Writer != "unknown" {
		t.Fatalf("строки: %+v", rows)
	}

	if rows[0].Service != defaultService {
		t.Fatalf("service: %q", rows[0].Service)
	}
}

func TestFromLogTruncates(t *testing.T) {
	long := strings.Repeat("x", maxText+10)

	rows, err := FromLog([]byte(`{"writer":"edge-01","lines":[{"text":"` + long + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}

	if len(rows[0].Text) != maxText {
		t.Fatalf("len: %d", len(rows[0].Text))
	}
}

func TestFromLogBadPayload(t *testing.T) {
	if _, err := FromLog([]byte("not json")); err == nil {
		t.Fatal("битая пачка обязана быть ошибкой")
	}
}
