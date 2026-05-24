//go:build custom

package config

import "net/http"

type customEvaluator struct{}

func NewEvaluator() Evaluator {
	return customEvaluator{}
}

func (customEvaluator) Evaluate(ctx Context, _ *http.Request, hasValidCookie bool) Decision {
	if !hasValidCookie {
		if ctx.Path == "/knock" {
			return Decision{Kind: DecisionIssueCookieAndRedirect, RedirectPath: "/", SetCookie: true, AllowReason: "knock"}
		}
		return Decision{Kind: DecisionDeny, AllowReason: "policy"}
	}

	return Decision{Kind: DecisionAllowProxy, Upstream: "http://127.0.0.1:8081", AllowReason: "custom_default"}
}
