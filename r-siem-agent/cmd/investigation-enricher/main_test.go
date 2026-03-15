package main

import (
	"context"
	"testing"

	"r-siem-agent/internal/investigation"
)

type stubProvider struct{ name string }

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) Supports(kind investigation.ObservableKind) bool {
	return true
}
func (s stubProvider) Enrich(ctx context.Context, obs investigation.Observable) (investigation.ProviderResult, error) {
	return investigation.ProviderResult{}, nil
}

func TestParseEnabledProviders(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty means all", raw: "", want: nil},
		{name: "all means all", raw: "all", want: nil},
		{name: "trim and normalize", raw: " VirusTotal , AbuseIPDB ", want: []string{"virustotal", "abuseipdb"}},
		{name: "drops blanks", raw: "virustotal,,", want: []string{"virustotal"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseEnabledProviders(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("len=%d want=%d got=%v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got=%v want=%v", got, tc.want)
				}
			}
		})
	}
}

func TestSelectProviders(t *testing.T) {
	all := []investigation.Provider{
		stubProvider{name: "greynoise"},
		stubProvider{name: "abuseipdb"},
		stubProvider{name: "virustotal"},
	}

	t.Run("default all", func(t *testing.T) {
		got, err := selectProviders(all, nil)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("len=%d want=3", len(got))
		}
	})

	t.Run("subset in requested order", func(t *testing.T) {
		got, err := selectProviders(all, []string{"virustotal", "greynoise"})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("len=%d want=2", len(got))
		}
		if got[0].Name() != "virustotal" || got[1].Name() != "greynoise" {
			t.Fatalf("unexpected provider order: %s,%s", got[0].Name(), got[1].Name())
		}
	})

	t.Run("unknown provider errors", func(t *testing.T) {
		_, err := selectProviders(all, []string{"virustotal", "bogus"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
