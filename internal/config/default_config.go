//go:build !custom

package config

import (
	"net/http"
	"strings"
)

type defaultEvaluator struct{}

func NewEvaluator() Evaluator {
	return defaultEvaluator{}
}

func (defaultEvaluator) Evaluate(ctx Context, _ *http.Request, hasValidCookie bool) Decision {
	if hasValidCookie {
		if upstream, ok := defaultHostUpstreams()[ctx.Host]; ok {
			return Decision{Kind: DecisionAllowProxy, Upstream: upstream, AllowReason: "cookie"}
		}
		return Decision{Kind: DecisionDeny, AllowReason: "unknown_host"}
	}

	if upstream, ok := defaultHostUpstreams()[ctx.Host]; ok {
		if strings.HasPrefix(ctx.Path, "/public") {
			return Decision{Kind: DecisionAllowProxy, Upstream: upstream, AllowReason: "public_path"}
		}
		if strings.HasPrefix(strings.ToLower(ctx.UA), "healthcheck") {
			return Decision{Kind: DecisionAllowProxy, Upstream: upstream, AllowReason: "ua_whitelist"}
		}
		if ctx.Path == "/knock" {
			return Decision{Kind: DecisionIssueCookieAndRedirect, RedirectPath: "/", SetCookie: true, AllowReason: "knock"}
		}
		return Decision{Kind: DecisionDeny, AllowReason: "policy"}
	}

	return Decision{Kind: DecisionDeny, AllowReason: "unknown_host"}
}

func defaultHostUpstreams() map[string]string {
	return map[string]string{
		"example.local": "http://127.0.0.1:8081",
	}
}
