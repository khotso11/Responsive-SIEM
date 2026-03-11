package main

import "testing"

func TestMergeFileAction(t *testing.T) {
	tests := []struct {
		current string
		next    string
		want    string
	}{
		{current: "", next: "created", want: "created"},
		{current: "created", next: "attrib", want: "created"},
		{current: "created", next: "modified", want: "modified"},
		{current: "modified", next: "deleted", want: "deleted"},
		{current: "deleted", next: "modified", want: "deleted"},
		{current: "attrib", next: "moved", want: "moved"},
	}
	for _, tt := range tests {
		if got := mergeFileAction(tt.current, tt.next); got != tt.want {
			t.Fatalf("mergeFileAction(%q, %q)=%q, want %q", tt.current, tt.next, got, tt.want)
		}
	}
}
