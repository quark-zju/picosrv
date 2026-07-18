package config

import "strings"

type defaultEvaluator struct{}

var defaultHostUpstreams = map[string]string{
	"example.local": "http://127.0.0.1:8081",
}

func NewEvaluator() Evaluator {
	if evaluatorFactory != nil {
		return evaluatorFactory()
	}
	return defaultEvaluator{}
}

func (defaultEvaluator) Evaluate(req EvaluationRequest) Decision {
	ctx := req.Context
	if req.Auth.HasValidCookie() {
		if upstream, ok := defaultHostUpstreams[ctx.Host]; ok {
			return Decision{Kind: DecisionAllowProxy, Upstream: upstream, Reason: "cookie"}
		}
		return Decision{Kind: DecisionDeny, Reason: "unknown_host"}
	}

	if upstream, ok := defaultHostUpstreams[ctx.Host]; ok {
		if strings.HasPrefix(ctx.Path, "/public") {
			return Decision{Kind: DecisionAllowProxy, Upstream: upstream, Reason: "public_path"}
		}
		// Demo-only shortcut: this default config is an example baseline.
		// Real deployments should replace this file (or use custom build tag policy)
		// and avoid trusting User-Agent alone for access control decisions.
		if strings.HasPrefix(strings.ToLower(ctx.UA), "healthcheck") {
			return Decision{Kind: DecisionAllowProxy, Upstream: upstream, Reason: "ua_whitelist"}
		}
		if ctx.Path == "/knock" {
			return Decision{Kind: DecisionIssueCookieAndRedirect, RedirectPath: "/", SetCookie: true, Reason: "knock"}
		}
		return Decision{Kind: DecisionDeny, Reason: "policy"}
	}

	return Decision{Kind: DecisionDeny, Reason: "unknown_host"}
}

func (defaultEvaluator) IsAllowedHTTPHost(host string) bool {
	_, ok := defaultHostUpstreams[host]
	return ok
}
