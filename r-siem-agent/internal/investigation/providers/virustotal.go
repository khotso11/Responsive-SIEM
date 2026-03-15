package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"r-siem-agent/internal/investigation"
)

type VirusTotalProvider struct {
	apiKey string
	client *http.Client
	retry  retryConfig
}

func NewVirusTotal() *VirusTotalProvider {
	key := os.Getenv("VT_API_KEY")
	return &VirusTotalProvider{
		apiKey: key,
		client: &http.Client{Timeout: 6 * time.Second},
		retry:  retryConfig{attempts: 2, baseBackoff: 400 * time.Millisecond},
	}
}

func (p *VirusTotalProvider) Name() string { return "virustotal" }

func (p *VirusTotalProvider) Supports(kind investigation.ObservableKind) bool {
	return kind == investigation.ObservableIP ||
		kind == investigation.ObservableDomain ||
		kind == investigation.ObservableURL ||
		kind == investigation.ObservableSHA256
}

func (p *VirusTotalProvider) Enrich(ctx context.Context, obs investigation.Observable) (investigation.ProviderResult, error) {
	if p.apiKey == "" {
		return investigation.ProviderResult{
			Provider: p.Name(),
			Status:   "skipped_no_api_key",
			Verdict:  "unknown",
			Summary:  "VT_API_KEY not set",
			Data:     map[string]any{},
		}, nil
	}

	path := ""
	switch obs.Kind {
	case investigation.ObservableIP:
		path = "/api/v3/ip_addresses/" + obs.Value
	case investigation.ObservableDomain:
		path = "/api/v3/domains/" + obs.Value
	case investigation.ObservableSHA256:
		path = "/api/v3/files/" + obs.Value
	case investigation.ObservableURL:
		// VT requires URL identifier base64 (without padding)
		enc := base64.RawStdEncoding.EncodeToString([]byte(obs.Value))
		path = "/api/v3/urls/" + enc
	default:
		return investigation.ProviderResult{Provider: p.Name(), Status: "skipped", Verdict: "unknown", Summary: "kind not supported", Data: map[string]any{}}, nil
	}

	endpoint := "https://www.virustotal.com" + path
	resp, meta, err := doRequestWithRetry(ctx, p.client, p.retry, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-apikey", p.apiKey)
		return req, nil
	})
	if err != nil {
		res := investigation.ErrorResult(p.Name(), err)
		res.Data = attachRequestMeta(res.Data, meta)
		return res, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return investigation.ProviderResult{Provider: p.Name(), Status: "rate_limited", Verdict: "unknown", Summary: "VirusTotal rate limited", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return investigation.ProviderResult{Provider: p.Name(), Status: "auth_failed", Verdict: "unknown", Summary: "VirusTotal auth failed", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout {
		return investigation.ProviderResult{Provider: p.Name(), Status: "timeout", Verdict: "unknown", Summary: "VirusTotal request timed out", Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode >= 500 {
		return investigation.ProviderResult{Provider: p.Name(), Status: "upstream_error", Verdict: "unknown", Summary: fmt.Sprintf("VirusTotal upstream error (%d)", resp.StatusCode), Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}
	if resp.StatusCode >= 400 {
		return investigation.ProviderResult{Provider: p.Name(), Status: "error", Verdict: "unknown", Summary: fmt.Sprintf("VirusTotal http %d", resp.StatusCode), Data: attachRequestMeta(map[string]any{}, meta)}, nil
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		res := investigation.ErrorResult(p.Name(), err)
		res.Data = attachRequestMeta(res.Data, meta)
		return res, nil
	}

	data := body
	verdict := "unknown"
	score := 0
	// try to pull stats
	if d, ok := data["data"].(map[string]any); ok {
		if attrs, ok := d["attributes"].(map[string]any); ok {
			if stats, ok := attrs["last_analysis_stats"].(map[string]any); ok {
				malicious := int(statsFloat(stats, "malicious"))
				suspicious := int(statsFloat(stats, "suspicious"))
				harmless := int(statsFloat(stats, "harmless"))
				score = malicious*2 + suspicious
				switch {
				case malicious > 0:
					verdict = "malicious"
				case suspicious > 0:
					verdict = "suspicious"
				case harmless > 0:
					verdict = "benign"
				}
			}
			if rep, ok := attrs["reputation"].(float64); ok && verdict == "unknown" {
				if rep > 5 {
					verdict = "malicious"
				} else if rep < -5 {
					verdict = "benign"
				}
				score = int(rep)
			}
		}
	}
	if score == 0 && verdict == "unknown" {
		score = 0
	}
	summary := fmt.Sprintf("VT: %s (score %d)", verdict, score)
	now := time.Now().UnixMilli()
	return investigation.ProviderResult{
		Provider:      p.Name(),
		Status:        "ok",
		Verdict:       verdict,
		Score:         score,
		Summary:       summary,
		EvidenceURL:   "https://www.virustotal.com/gui/search/" + obs.Value,
		FetchedAtUnix: now,
		ExpiresAtUnix: now + 12*60*60*1000,
		Data:          attachRequestMeta(data, meta),
	}, nil
}

func statsFloat(m map[string]any, key string) float64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return 0
}
