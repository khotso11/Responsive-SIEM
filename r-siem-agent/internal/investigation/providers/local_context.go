package providers

import (
	"net"
	"net/url"
	"strings"
	"time"

	"r-siem-agent/internal/investigation"
)

func localProviderFallback(provider string, obs investigation.Observable, missingKey bool) investigation.ProviderResult {
	now := time.Now().UnixMilli()
	status := "ok_local_context"
	if missingKey {
		status = "ok_local_fallback"
	}
	result := investigation.ProviderResult{
		Provider:      provider,
		Status:        status,
		Verdict:       "unknown",
		Score:         0,
		FetchedAtUnix: now,
		ExpiresAtUnix: now + 60*60*1000,
		Data: map[string]any{
			"lookup_mode":       "local_context",
			"api_key_missing":   missingKey,
			"observable_role":   obs.Role,
			"observable_source": obs.Source,
		},
	}

	switch obs.Kind {
	case investigation.ObservableIP:
		result = localIPFallback(provider, result, obs.Value)
	case investigation.ObservableDomain:
		result = localDomainFallback(provider, result, obs.Value)
	case investigation.ObservableURL:
		result = localURLFallback(provider, result, obs.Value)
	case investigation.ObservableSHA256:
		result.Summary = "Hash observable collected. Local context only; provider API key is not configured."
		result.Data["kind"] = "sha256"
	}
	return result
}

func localIPFallback(provider string, res investigation.ProviderResult, raw string) investigation.ProviderResult {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		res.Summary = "IP observable is invalid; provider lookup was not attempted."
		return res
	}
	switch {
	case ip.IsLoopback():
		res.Verdict = "benign"
		res.Summary = "Loopback IP; external reputation is not applicable."
		res.Score = 0
	case ip.IsPrivate():
		res.Verdict = "benign"
		res.Summary = "Private/internal IP; use incident context rather than external reputation."
		res.Score = 0
	case ip.IsMulticast() || ip.IsUnspecified():
		res.Verdict = "unknown"
		res.Summary = "Reserved IP space; external reputation is not meaningful."
	default:
		if isDocumentationIPv4(ip) {
			res.Verdict = "benign"
			res.Summary = "Documentation/demo IP range; external reputation is intentionally not applicable."
			res.Score = 0
		} else {
			res.Verdict = "unknown"
			res.Summary = "Public IP collected, but provider API key is not configured; treat as unverified until external lookup is enabled."
			res.Score = 10
		}
	}
	res.Data["kind"] = "ip"
	res.Data["ip"] = raw
	return res
}

func localDomainFallback(provider string, res investigation.ProviderResult, raw string) investigation.ProviderResult {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case value == "":
		res.Summary = "Domain observable is empty."
	case strings.HasSuffix(value, ".local") || strings.HasSuffix(value, ".internal") || strings.HasSuffix(value, ".lan"):
		res.Verdict = "benign"
		res.Summary = "Internal naming domain; external reputation is not applicable."
	case value == "localhost":
		res.Verdict = "benign"
		res.Summary = "localhost is internal-only; external reputation is not applicable."
	default:
		res.Verdict = "unknown"
		res.Score = 10
		res.Summary = "Domain collected, but provider API key is not configured; treat as unverified until external lookup is enabled."
	}
	res.Data["kind"] = "domain"
	res.Data["domain"] = raw
	return res
}

func localURLFallback(provider string, res investigation.ProviderResult, raw string) investigation.ProviderResult {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		res.Summary = "URL observable is invalid; provider lookup was not attempted."
		return res
	}
	host := strings.ToLower(u.Hostname())
	res = localDomainFallback(provider, res, host)
	res.Data["kind"] = "url"
	res.Data["url"] = raw
	return res
}

func isDocumentationIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2:
		return true
	case ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100:
		return true
	case ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113:
		return true
	default:
		return false
	}
}
