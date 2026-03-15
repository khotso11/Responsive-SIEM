package providers

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type retryConfig struct {
	attempts    int
	baseBackoff time.Duration
}

type requestMeta struct {
	Attempts   int
	LatencyMs  int64
	HTTPStatus int
	ErrorClass string
}

func doRequestWithRetry(ctx context.Context, client *http.Client, cfg retryConfig, build func() (*http.Request, error)) (*http.Response, requestMeta, error) {
	if cfg.attempts <= 0 {
		cfg.attempts = 1
	}
	if cfg.baseBackoff <= 0 {
		cfg.baseBackoff = 200 * time.Millisecond
	}
	start := time.Now()
	meta := requestMeta{}
	var lastErr error
	for attempt := 1; attempt <= cfg.attempts; attempt++ {
		req, err := build()
		if err != nil {
			meta.Attempts = attempt
			meta.LatencyMs = time.Since(start).Milliseconds()
			return nil, meta, err
		}
		resp, err := client.Do(req)
		meta.Attempts = attempt
		meta.LatencyMs = time.Since(start).Milliseconds()
		if err == nil {
			meta.HTTPStatus = resp.StatusCode
			if !shouldRetryStatus(resp.StatusCode) || attempt == cfg.attempts {
				if shouldRetryStatus(resp.StatusCode) {
					meta.ErrorClass = "upstream_error"
				}
				return resp, meta, nil
			}
			meta.ErrorClass = "upstream_error"
			drainAndClose(resp.Body)
			if err := sleepContext(ctx, backoffDuration(cfg.baseBackoff, attempt)); err != nil {
				return nil, meta, err
			}
			continue
		}
		lastErr = err
		meta.ErrorClass = classifyRetryError(err)
		if !shouldRetryError(err) || attempt == cfg.attempts {
			return nil, meta, err
		}
		if err := sleepContext(ctx, backoffDuration(cfg.baseBackoff, attempt)); err != nil {
			return nil, meta, err
		}
	}
	meta.LatencyMs = time.Since(start).Milliseconds()
	return nil, meta, lastErr
}

func attachRequestMeta(data map[string]any, meta requestMeta) map[string]any {
	if data == nil {
		data = map[string]any{}
	}
	data["_request"] = map[string]any{
		"attempts":    meta.Attempts,
		"latency_ms":  meta.LatencyMs,
		"http_status": meta.HTTPStatus,
		"error_class": meta.ErrorClass,
	}
	return data
}

func shouldRetryStatus(code int) bool {
	return code == http.StatusRequestTimeout || code >= 500
}

func shouldRetryError(err error) bool {
	return classifyRetryError(err) == "timeout" || classifyRetryError(err) == "network_error"
}

func classifyRetryError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	default:
		var netErr net.Error
		if errors.As(err, &netErr) {
			if netErr.Timeout() {
				return "timeout"
			}
			return "network_error"
		}
		return "error"
	}
}

func backoffDuration(base time.Duration, attempt int) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}
	return time.Duration(attempt) * base
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
