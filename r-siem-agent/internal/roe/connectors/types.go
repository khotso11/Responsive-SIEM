package connectors

import (
	"context"
	"errors"
)

type Step struct {
	ActionType string
	Target     string
	RunID      string
	StepID     string
	StepIndex  int
	Lane       string
	Params     map[string]any
	TimeoutMs  *int64
}

type Connector interface {
	Name() string
	ActionType() string
	RequiredParams() []string
	OptionalParams() []string
	Execute(ctx context.Context, step Step) (map[string]any, error)
}

type RetryableError struct {
	Err error
}

func (e *RetryableError) Error() string {
	if e == nil || e.Err == nil {
		return "retryable_error"
	}
	return e.Err.Error()
}

func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return &RetryableError{Err: err}
}

func IsRetryable(err error) bool {
	var retryable *RetryableError
	return errors.As(err, &retryable)
}
