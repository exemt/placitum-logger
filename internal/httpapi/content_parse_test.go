package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseHeadersFragmentComplete(t *testing.T) {
	pairs, cont := parseHeadersFragment([]byte(`[["host","shop.example.com"],["ua","curl"]]`))
	if cont != "" {
		t.Fatalf("continuation = %q", cont)
	}
	if len(pairs) != 2 || pairs[0].Name != "host" || pairs[1].Value != "curl" {
		t.Fatalf("pairs = %#v", pairs)
	}
}

func TestParseHeadersFragmentTruncatedValue(t *testing.T) {
	raw := `[["host","a.com"],["x-load-pad","` + strings.Repeat("x", 40)
	pairs, cont := parseHeadersFragment([]byte(raw))
	if cont != "" {
		t.Fatalf("continuation = %q", cont)
	}
	if len(pairs) != 2 {
		t.Fatalf("len = %d, want 2", len(pairs))
	}
	if pairs[1].Name != "x-load-pad" || pairs[1].Value != strings.Repeat("x", 40) {
		t.Fatalf("pad = %#v", pairs[1])
	}
}

func TestParseHeadersFragmentContinuation(t *testing.T) {
	pairs, cont := parseHeadersFragment([]byte(strings.Repeat("x", 12)))
	if len(pairs) != 0 {
		t.Fatalf("pairs = %#v", pairs)
	}
	if cont != strings.Repeat("x", 12) {
		t.Fatalf("continuation = %q", cont)
	}
}

func TestParseHeadersFragmentNextPair(t *testing.T) {
	pairs, cont := parseHeadersFragment([]byte(`,["ua","curl"],["x","y"]`))
	if cont != "" {
		t.Fatalf("continuation = %q", cont)
	}
	if len(pairs) != 2 || pairs[0].Name != "ua" || pairs[1].Name != "x" {
		t.Fatalf("pairs = %#v", pairs)
	}
}

func TestParseArgsFragment(t *testing.T) {
	pairs, cont := parseArgsFragment("a=1&b=2", 0)
	if cont != "" || len(pairs) != 2 || pairs[1].Name != "b" {
		t.Fatalf("pairs=%#v cont=%q", pairs, cont)
	}

	pairs, cont = parseArgsFragment("ue&c=3", 10)
	if cont != "ue" || len(pairs) != 1 || pairs[0].Name != "c" {
		t.Fatalf("pairs=%#v cont=%q", pairs, cont)
	}

	pairs, cont = parseArgsFragment("only", 10)
	if len(pairs) != 0 || cont != "only" {
		t.Fatalf("pairs=%#v cont=%q", pairs, cont)
	}
}

func TestUTF8Window(t *testing.T) {
	text, n, ok := utf8Window([]byte("abc"))
	if !ok || text != "abc" || n != 3 {
		t.Fatalf("text=%q n=%d ok=%v", text, n, ok)
	}

	text, n, ok = utf8Window([]byte{'a', 0xD0})
	if !ok || text != "a" || n != 1 {
		t.Fatalf("split: text=%q n=%d ok=%v", text, n, ok)
	}

	_, _, ok = utf8Window([]byte{'a', 0})
	if ok {
		t.Fatal("nul must be binary")
	}
}

func TestWindowOf(t *testing.T) {
	max := int64(256 << 10)

	offset, limit := windowOf(get(""), max)
	if offset != 0 || limit != max {
		t.Fatalf("default offset=%d limit=%d", offset, limit)
	}

	offset, limit = windowOf(get("offset=10&limit=32"), max)
	if offset != 10 || limit != 32 {
		t.Fatalf("window offset=%d limit=%d", offset, limit)
	}

	offset, limit = windowOf(get("offset=0"), max)
	if offset != 0 || limit != defaultViewChunk {
		t.Fatalf("chunk default offset=%d limit=%d", offset, limit)
	}

	_, limit = windowOf(get("limit=999999999"), max)
	if limit != max {
		t.Fatalf("limit above max = %d", limit)
	}
}

func get(rawQuery string) *http.Request {
	url := "/api/audit/n/r/headers"
	if rawQuery != "" {
		url += "?" + rawQuery
	}

	return httptest.NewRequest(http.MethodGet, url, nil)
}
