package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"r-siem-agent/internal/investigation"
)

type GreyNoiseProvider struct {
	apiKey string
	client *http.Client
	retry  retryConfig
}

func NewGreyNoise() *GreyNoiseProvider {
	key := os.Getenv("GREYNOISE_API_KEY")
	return &GreyNoiseProvider{
		apiKey: key,
		client: &http.Client{Timeout: 5 * time.Second},
		retry:  retryConfig{attempts: 2, baseBackoff: 250 * time.Millisecond},
	}
}

func (p *GreyNoiseProvider) Name() string { return "greynoise" }

func (p *GreyNoiseProvider) Supports(kind investigation.ObservableKind) bool {
	return kind == investigation.ObservableIP
}

func (p *GreyNoiseProvider) Enrich(ctx context.Context, obs investigation.Observable) (investigation.ProviderResult, error) {
	if p.apiKey == "" {
		return investigation.ProviderResult{
			Provider: p.Name(),
			Status:   "skipped_no_api_key",
			Verdict:  "unknown",
			Summary:  "GREYNOISE_API_KEY not set",
			Data:     map[string]any{},
		}, nil
	}

	endpoint := "https://api.greynoise.io/v3/community/" + obs.Value
	resp, meta, err := doRequestWithRetry(ctx, p.client, p.retry, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("key", p.apiKey)
		return req, nil
	})
	if err != nil {
		res := investigation.ErrorResult(p.Name(), err)
		res.Data = attachRequestMeta(res.Data, meta)
		return res, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return investigation.ProviderResult{Provider: p.Name(), Status: "rate_limited", Verdict: "unknown", Summary: "GreyNoise rate limited", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return investigation.ProviderResult{Provider: p.Name(), Status: "auth_failed", Verdict: "unknown", Summary: "GreyNoise auth failed", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout {
		return investigation.ProviderResult{Provider: p.Name(), Status: "timeout", Verdict: "unknown", Summary: "GreyNoise request timed out", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode >= 500 {
		return investigation.ProviderResult{Provider: p.Name(), Status: "upstream_error", Verdict: "unknown", Summary: fmt.Sprintf("GreyNoise upstream error (%d)", resp.StatusCode), Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode >= 400 {
		return investigation.ProviderResult{Provider: p.Name(), Status: "error", Verdict: "unknown", Summary: fmt.Sprintf("GreyNoise http %d", resp.StatusCode), Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		res := investigation.ErrorResult(p.Name(), err)
		res.Data = attachRequestMeta(res.Data, meta)
		return res, nil
	}

	verdict := strings.ToLower(fmt.Sprint(body["classification"]))
	if verdict == "" || verdict == "none" {
		verdict = "unknown"
	}
	summary := strings.TrimSpace(fmt.Sprint(body["name"]))
	if summary == "" {
		summary = fmt.Sprintf("GreyNoise: %s", verdict)
	}
	score := 0
	if v, ok := body["noise"]; ok {
		if vb, okb := v.(bool); okb && vb {
			score = 30
		}
	}
	now := time.Now().UnixMilli()
	return investigation.ProviderResult{
		Provider:      p.Name(),
		Status:        "ok",
		Verdict:       verdict,
		Score:         score,
		Summary:       summary,
		EvidenceURL:   "https://viz.greynoise.io/ip/" + obs.Value,
		FetchedAtUnix: now,
		ExpiresAtUnix: now + 24*60*60*1000,
		Data:          attachRequestMeta(body, meta),
	}, nil
}
