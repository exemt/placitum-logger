package store

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

/*
 * Срок объекта в записи есть, и он вышел. Ответ даётся без похода в хранилище:
 * оно ответило бы то же самое, но на round-trip позже, а под нагрузкой разбора
 * инцидентов это единственная разница между карточкой и ожиданием карточки.
 *
 * Неизвестный срок — не истёкший: за объектом идут как ни в чём не бывало.
 */
func TestFetchTrustsExpiry(t *testing.T) {
	var asked atomic.Int64

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			asked.Add(1)
			_, _ = w.Write([]byte(`[["host","example.com"]]`))
		}))

	defer archive.Close()

	reader := New(Config{
		S3:     S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket: map[string]string{"headers": "waf-headers"},
	})

	loc := Locator{
		Size:   59,
		Store:  "archive",
		Driver: "s3",
		Key:    "2026/08/16/edge-01/r.hdr",
	}

	cases := []struct {
		name   string
		in     int64
		reason string
		asked  int64
	}{
		{
			name:   "срок вышел",
			in:     time.Now().Add(-time.Minute).Unix(),
			reason: ReasonTTL,
			asked:  0,
		},
		{
			name:  "срок ещё не вышел",
			in:    time.Now().Add(time.Hour).Unix(),
			asked: 1,
		},
		{
			name:  "срока нет: правила удаления в бакете не заведено",
			in:    0,
			asked: 2,
		},
	}

	for _, item := range cases {
		loc.ExpiresAt = item.in

		got, err := reader.Fetch(context.Background(), "headers", loc, true)
		if err != nil {
			t.Fatalf("%s: %v", item.name, err)
		}

		if got.Reason != item.reason {
			t.Fatalf("%s: reason = %q, want %q",
				item.name, got.Reason, item.reason)
		}

		if n := asked.Load(); n != item.asked {
			t.Fatalf("%s: archive was asked %d times, want %d",
				item.name, n, item.asked)
		}
	}
}

// Локатор без адресации к хранилищу не ведёт: срока в нём тоже нет, и путать
// «не удержали» с «удалили по сроку» нельзя — это разные разговоры с оператором.
func TestFetchSeparatesDiscardedFromExpiry(t *testing.T) {
	reader := New(Config{})

	loc, ok := ParseLocator(`{"size":59}`)
	if !ok {
		t.Fatal("locator is not readable")
	}

	if loc.Expired(time.Now()) {
		t.Fatal("a locator without an address cannot expire")
	}

	got, err := reader.Fetch(context.Background(), "headers", loc, ok)
	if err != nil {
		t.Fatal(err)
	}

	if got.Reason != ReasonDiscarded {
		t.Fatalf("reason = %q, want %q", got.Reason, ReasonDiscarded)
	}
}

func TestFetchWindowSlicesObject(t *testing.T) {
	object := []byte("abcdefghij")

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(object)
		}))

	defer archive.Close()

	reader := New(Config{
		S3:       S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:   map[string]string{"body": "waf-body"},
		MaxBytes: 64,
	})

	loc := Locator{
		Size:   int64(len(object)),
		Store:  "archive",
		Driver: "s3",
		Key:    "k",
	}

	got, err := reader.FetchWindow(context.Background(), "body", loc, true, 2, 4)
	if err != nil {
		t.Fatal(err)
	}

	if string(got.Data) != "cdef" {
		t.Fatalf("data = %q", got.Data)
	}

	if !got.Clipped {
		t.Fatal("locator size is greater than this window")
	}
}
