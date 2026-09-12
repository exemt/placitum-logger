/*
 * Разбор пачки. Зеркало упаковки в агенте
 * (nginx/agent/internal/audit/sink.go): элемент пачки -- это обычная запись,
 * и вид у неё читается тем же KindOf.
 */

package model

import "testing"

func TestBatchUnpacksItems(t *testing.T) {
	payload := []byte(`{"v":1,"kind":"batch","node":"edge-01","items":[` +
		`{"v":1,"kind":"request","ray":"r1"},` +
		`{"v":1,"kind":"inspector","ray":"r2"}]}`)

	items, ok := Batch(payload)
	if !ok {
		t.Fatal("a batch envelope must read as a batch")
	}

	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}

	if got := KindOf(items[0]); got != KindRequest {
		t.Errorf("items[0] kind = %q, want %q", got, KindRequest)
	}

	if got := KindOf(items[1]); got != KindInspector {
		t.Errorf("items[1] kind = %q, want %q", got, KindInspector)
	}
}

// Одиночная запись пачкой не считается: иначе разбор зависел бы от догадки,
// а не от конверта.
func TestBatchRejectsOtherKinds(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"v":1,"kind":"request","ray":"r1"}`),
		[]byte(`{"v":1,"kind":"inspector","ray":"r1"}`),
		[]byte(`not json`),
		nil,
	} {
		if _, ok := Batch(payload); ok {
			t.Errorf("Batch(%s) = true, want false", payload)
		}
	}
}

// Пустая пачка законна: писатель мог отправить её на закрытии, и разбор
// обязан вернуть "это пачка, записей нет", а не "это не пачка".
func TestBatchAcceptsEmptyItems(t *testing.T) {
	items, ok := Batch([]byte(`{"v":1,"kind":"batch","items":[]}`))

	if !ok {
		t.Fatal("an empty batch is still a batch")
	}

	if len(items) != 0 {
		t.Errorf("items = %d, want none", len(items))
	}
}
