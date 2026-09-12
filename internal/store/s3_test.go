package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestRangeHasMore(t *testing.T) {
	cases := []struct {
		hdr  string
		next int64
		more bool
		ok   bool
	}{
		{"bytes 0-32767/90000", 32768, true, true},
		{"bytes 0-99/100", 100, false, true},
		{"bytes 32-63/64", 64, false, true},
		{"bytes 0-10/*", 11, false, false},
		{"", 10, false, false},
	}

	for _, item := range cases {
		more, ok := rangeHasMore(item.hdr, item.next)
		if ok != item.ok || more != item.more {
			t.Fatalf("%q next=%d: more=%v ok=%v, want more=%v ok=%v",
				item.hdr, item.next, more, ok, item.more, item.ok)
		}
	}
}

func TestGetWindowUsesRange(t *testing.T) {
	object := strings.Repeat("x", 100)

	var gotRange string

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotRange = r.Header.Get("Range")
			start, end := 0, len(object)-1
			if rng := r.Header.Get("Range"); strings.HasPrefix(rng, "bytes=") {
				spec := strings.TrimPrefix(rng, "bytes=")
				left, right, _ := strings.Cut(spec, "-")
				if n, err := strconv.Atoi(left); err == nil {
					start = n
				}
				if n, err := strconv.Atoi(right); err == nil {
					end = n
				}
			}
			if start >= len(object) {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			if end >= len(object) {
				end = len(object) - 1
			}

			w.Header().Set("Content-Range",
				"bytes "+strconv.Itoa(start)+"-"+strconv.Itoa(end)+"/"+strconv.Itoa(len(object)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, object[start:end+1])
		}))

	defer archive.Close()

	c := testClient(archive.URL)

	data, clipped, err := c.get(context.Background(), "hdr", "k", 10, 20)
	if err != nil {
		t.Fatal(err)
	}

	if gotRange != "bytes=10-29" {
		t.Fatalf("Range = %q, want bytes=10-29", gotRange)
	}

	if string(data) != strings.Repeat("x", 20) {
		t.Fatalf("data = %q", data)
	}

	if !clipped {
		t.Fatal("expected more bytes after this window")
	}

	tail, clipped, err := c.get(context.Background(), "hdr", "k", 90, 20)
	if err != nil {
		t.Fatal(err)
	}

	if len(tail) != 10 || clipped {
		t.Fatalf("tail len=%d clipped=%v", len(tail), clipped)
	}
}

func TestGetWindowFullBodyIgnoresRange(t *testing.T) {
	object := []byte("abcdefghij")

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(object)
		}))

	defer archive.Close()

	c := testClient(archive.URL)

	data, clipped, err := c.get(context.Background(), "hdr", "k", 2, 4)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != "cdef" {
		t.Fatalf("data = %q, want cdef", data)
	}

	if !clipped {
		t.Fatal("object continues after this window")
	}

	rest, clipped, err := c.get(context.Background(), "hdr", "k", 8, 4)
	if err != nil {
		t.Fatal(err)
	}

	if string(rest) != "ij" || clipped {
		t.Fatalf("rest = %q clipped=%v", rest, clipped)
	}
}

func TestGetWindowPastEnd(t *testing.T) {
	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			_, _ = io.WriteString(w, "unsatisfiable")
		}))

	defer archive.Close()

	c := testClient(archive.URL)

	data, clipped, err := c.get(context.Background(), "hdr", "k", 100, 20)
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != 0 || clipped {
		t.Fatalf("data=%q clipped=%v", data, clipped)
	}
}

func testClient(endpoint string) *s3Client {
	return &s3Client{
		endpoint: endpoint,
		region:   "us-east-1",
		access:   "k",
		secret:   "s",
		http:     http.DefaultClient,
	}
}
