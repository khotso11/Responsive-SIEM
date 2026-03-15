package investigation

import (
	"context"
)

// Engine orchestrates provider fanout and simple in-memory provider list.
type Engine struct {
	providers []Provider
}

func NewEngine(providers ...Provider) *Engine {
	return &Engine{providers: providers}
}

func (e *Engine) Providers() []Provider {
	return e.providers
}

// Enrich dispatches to providers that support the observable kind.
// Caching, TTL, privacy filtering, and DB writes will be layered later.
func (e *Engine) Enrich(ctx context.Context, obs Observable) ([]ProviderResult, error) {
	var results []ProviderResult
	for _, p := range e.providers {
		if !p.Supports(obs.Kind) {
			continue
		}
		res, err := p.Enrich(ctx, obs)
		if err != nil {
			results = append(results, ErrorResult(p.Name(), err))
			continue
		}
		results = append(results, res)
	}
	return results, nil
}
