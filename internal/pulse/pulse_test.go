package pulse

import "testing"

func TestSubject(t *testing.T) {
	got := Subject("logger", "abc.def")
	want := "WAF_STATUS.service.logger.abc_def"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
