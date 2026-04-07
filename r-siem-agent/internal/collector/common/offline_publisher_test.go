package common

import (
	"errors"
	"os"
	"testing"
)

func TestShouldRetryWithFallback(t *testing.T) {
	if !shouldRetryWithFallback(os.ErrPermission) {
		t.Fatal("expected permission errors to trigger fallback")
	}
	if !shouldRetryWithFallback(os.ErrNotExist) {
		t.Fatal("expected missing-path errors to trigger fallback")
	}
	if shouldRetryWithFallback(errors.New("other")) {
		t.Fatal("unexpected fallback for generic error")
	}
}

func TestFallbackSpoolPathUsesTmp(t *testing.T) {
	got := fallbackSpoolPath("collector-tail")
	want := "/tmp/collector-tail.spool.jsonl"
	if got != want {
		t.Fatalf("fallbackSpoolPath()=%q want %q", got, want)
	}
}
