package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"r-siem-agent/internal/investigation"
)

type AbuseIPDBProvider struct {
	apiKey string
	client *http.Client
	retry  retryConfig
}

func NewAbuseIPDB() *AbuseIPDBProvider {
	key := os.Getenv("ABUSEIPDB_API_KEY")
	return &AbuseIPDBProvider{
		apiKey: key,
		client: &http.Client{Timeout: 5 * time.Second},
		retry:  retryConfig{attempts: 3, baseBackoff: 350 * time.Millisecond},
	}
}

func (p *AbuseIPDBProvider) Name() string { return "abuseipdb" }

func (p *AbuseIPDBProvider) Supports(kind investigation.ObservableKind) bool {
	return kind == investigation.ObservableIP
}

func (p *AbuseIPDBProvider) Enrich(ctx context.Context, obs investigation.Observable) (investigation.ProviderResult, error) {
	if p.apiKey == "" {
		return investigation.ProviderResult{
			Provider: p.Name(),
			Status:   "skipped_no_api_key",
			Verdict:  "unknown",
			Summary:  "ABUSEIPDB_API_KEY not set",
			Data:     map[string]any{},
		}, nil
	}

	url := "https://api.abuseipdb.com/api/v2/check?ipAddress=" + obs.Value + "&maxAgeInDays=90"
	resp, meta, err := doRequestWithRetry(ctx, p.client, p.retry, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Key", p.apiKey)
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
	if err != nil {
		res := investigation.ErrorResult(p.Name(), err)
		res.Data = attachRequestMeta(res.Data, meta)
		return res, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return investigation.ProviderResult{Provider: p.Name(), Status: "rate_limited", Verdict: "unknown", Summary: "AbuseIPDB rate limited", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return investigation.ProviderResult{Provider: p.Name(), Status: "auth_failed", Verdict: "unknown", Summary: "AbuseIPDB auth failed", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout {
		return investigation.ProviderResult{Provider: p.Name(), Status: "timeout", Verdict: "unknown", Summary: "AbuseIPDB request timed out", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode >= 500 {
		return investigation.ProviderResult{Provider: p.Name(), Status: "upstream_error", Verdict: "unknown", Summary: fmt.Sprintf("AbuseIPDB upstream error (%d)", resp.StatusCode), Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode >= 400 {
		return investigation.ProviderResult{Provider: p.Name(), Status: "error", Verdict: "unknown", Summary: fmt.Sprintf("AbuseIPDB http %d", resp.StatusCode), Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}

	var wrapper struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		res := investigation.ErrorResult(p.Name(), err)
		res.Data = attachRequestMeta(res.Data, meta)
		return res, nil
	}

	data := wrapper.Data
	verdict := "unknown"
	score := 0
	if v, ok := data["abuseConfidenceScore"].(float64); ok {
		score = int(v)
		switch {
		case score >= 85:
			verdict = "malicious"
		case score >= 50:
			verdict = "suspicious"
		case score <= 5:
			verdict = "benign"
		}
	}
	summary := fmt.Sprintf("Abuse score %d/100", score)
	now := time.Now().UnixMilli()
	return investigation.ProviderResult{
		Provider:      p.Name(),
		Status:        "ok",
		Verdict:       verdict,
		Score:         score,
		Summary:       summary,
		EvidenceURL:   "https://abuseipdb.com/check/" + obs.Value,
		FetchedAtUnix: now,
		ExpiresAtUnix: now + 12*60*60*1000,
		Data:          attachRequestMeta(data, meta),
	}, nil
}
