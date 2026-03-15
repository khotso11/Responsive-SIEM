package investigation

import (
	"context"
)

type ObservableKind string

const (
	ObservableIP     ObservableKind = "ip"
	ObservableDomain ObservableKind = "domain"
	ObservableURL    ObservableKind = "url"
	ObservableSHA256 ObservableKind = "sha256"
)

type Observable struct {
	Kind   ObservableKind `json:"kind"`
	Value  string         `json:"value"`
	Role   string         `json:"role"`   // e.g. destination_ip, queried_domain
	Source string         `json:"source"` // e.g. incident.run.dst_ip
}

type ProviderResult struct {
	Provider      string         `json:"provider"`
	Status        string         `json:"status"`         // ok, error, skipped
	Verdict       string         `json:"verdict"`        // malicious, suspicious, noise, benign, unknown
	Score         int            `json:"score"`          // provider-native or normalized score
	Summary       string         `json:"summary"`        // short human summary
	EvidenceURL   string         `json:"evidence_url"`   // provider link
	FetchedAtUnix int64          `json:"fetched_at_unix_ms"`
	ExpiresAtUnix int64          `json:"expires_at_unix_ms"`
	Data          map[string]any `json:"data"` // provider-specific payload
}

type Provider interface {
	Name() string
	Supports(kind ObservableKind) bool
	Enrich(ctx context.Context, obs Observable) (ProviderResult, error)
}
