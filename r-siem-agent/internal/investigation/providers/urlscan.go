package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"r-siem-agent/internal/investigation"
)

type URLScanProvider struct {
	apiKey string
	client *http.Client
	retry  retryConfig
}

func NewURLScan() *URLScanProvider {
	key := os.Getenv("URLSCAN_API_KEY")
	return &URLScanProvider{
		apiKey: key,
		client: &http.Client{Timeout: 6 * time.Second},
		retry:  retryConfig{attempts: 2, baseBackoff: 500 * time.Millisecond},
	}
}

func (p *URLScanProvider) Name() string { return "urlscan" }

func (p *URLScanProvider) Supports(kind investigation.ObservableKind) bool {
	return kind == investigation.ObservableURL || kind == investigation.ObservableDomain
}

func (p *URLScanProvider) Enrich(ctx context.Context, obs investigation.Observable) (investigation.ProviderResult, error) {
	if p.apiKey == "" {
		return investigation.ProviderResult{
			Provider: p.Name(),
			Status:   "skipped_no_api_key",
			Verdict:  "unknown",
			Summary:  "URLSCAN_API_KEY not set",
			Data:     map[string]any{},
		}, nil
	}

	query := obs.Value
	if obs.Kind == investigation.ObservableDomain {
		query = "domain:" + obs.Value
	}
	endpoint := "https://urlscan.io/api/v1/search/?q=" + url.QueryEscape(query)
	resp, meta, err := doRequestWithRetry(ctx, p.client, p.retry, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("API-Key", p.apiKey)
		return req, nil
	})
	if err != nil {
		res := investigation.ErrorResult(p.Name(), err)
		res.Data = attachRequestMeta(res.Data, meta)
		return res, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return investigation.ProviderResult{Provider: p.Name(), Status: "rate_limited", Verdict: "unknown", Summary: "urlscan rate limited", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return investigation.ProviderResult{Provider: p.Name(), Status: "auth_failed", Verdict: "unknown", Summary: "urlscan auth failed", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout {
		return investigation.ProviderResult{Provider: p.Name(), Status: "timeout", Verdict: "unknown", Summary: "urlscan request timed out", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode >= 500 {
		return investigation.ProviderResult{Provider: p.Name(), Status: "upstream_error", Verdict: "unknown", Summary: fmt.Sprintf("urlscan upstream error (%d)", resp.StatusCode), Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode >= 400 {
		return investigation.ProviderResult{Provider: p.Name(), Status: "error", Verdict: "unknown", Summary: fmt.Sprintf("urlscan http %d", resp.StatusCode), Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		res := investigation.ErrorResult(p.Name(), err)
		res.Data = attachRequestMeta(res.Data, meta)
		return res, nil
	}

	verdict := "unknown"
	score := 0
	total := 0
	if results, ok := body["results"].([]any); ok {
		total = len(results)
	}
	summary := fmt.Sprintf("urlscan matches: %d", total)
	evidenceURL := "https://urlscan.io/search/#" + url.QueryEscape(query)
	now := time.Now().UnixMilli()
	return investigation.ProviderResult{
		Provider:      p.Name(),
		Status:        "ok",
		Verdict:       verdict,
		Score:         score,
		Summary:       summary,
		EvidenceURL:   evidenceURL,
		FetchedAtUnix: now,
		ExpiresAtUnix: now + 24*60*60*1000,
		Data:          attachRequestMeta(body, meta),
	}, nil
}
