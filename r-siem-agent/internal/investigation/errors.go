package investigation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
)

// ErrorResult normalizes transport/provider failures into stable statuses for DB/UI consumers.
func ErrorResult(provider string, err error) ProviderResult {
	status := "error"
	summary := fmt.Sprintf("%s error", provider)
	if err != nil {
		summary = err.Error()
	}
	switch {
	case err == nil:
		summary = ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded), isTimeoutError(err):
		status = "timeout"
		summary = fmt.Sprintf("%s request timed out", provider)
	case isNetworkError(err):
		status = "network_error"
		summary = fmt.Sprintf("%s network error", provider)
	}
	return ProviderResult{
		Provider: provider,
		Status:   status,
		Verdict:  "unknown",
		Summary:  summary,
		Data: map[string]any{
			"error": errorString(err),
		},
	}
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isNetworkError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
