package config

import (
	"net/http"
)

type DecisionKind int

const (
	DecisionDeny DecisionKind = iota
	// DecisionAllowProxy forwards to a private backend while preserving the
	// original inbound Host header. Use this for normal site reverse proxying
	// where the backend expects the public virtual host.
	DecisionAllowProxy
	// DecisionAllowExternalProxy forwards to an external API upstream using the
	// upstream URL's Host header. Use this for public API providers such as
	// https://api.openai.com or https://openrouter.ai, where sending the inbound
	// LAN/public gateway Host would be incorrect.
	DecisionAllowExternalProxy
	DecisionAllowFiles
	DecisionIssueCookieAndRedirect
	DecisionRequireBasicAuth
)

type Decision struct {
	Kind         DecisionKind
	Upstream     string
	RootDir      string
	Reason       string
	RedirectPath string
	SetCookie    bool
	Realm        string
}

type Context struct {
	Host  string
	Path  string
	UA    string
	Query map[string][]string
}

// RequestAuth provides request-scoped authentication operations to an
// Evaluator. Implementations may cache validation results for the lifetime of
// the request.
type RequestAuth interface {
	// HasValidCookie reports whether the request has a valid picosrv access
	// cookie.
	HasValidCookie() bool
}

// EvaluationRequest contains the normalized request data and request-scoped
// capabilities available to an Evaluator.
type EvaluationRequest struct {
	Context Context
	HTTP    *http.Request
	Auth    RequestAuth
}

type Evaluator interface {
	Evaluate(req EvaluationRequest) Decision
}

type HTTPHostValidator interface {
	IsAllowedHTTPHost(host string) bool
}

var evaluatorFactory func() Evaluator

// SetEvaluatorFactory installs a process-local evaluator factory override.
// Intended for local customization via ignored files (e.g. custom_local.go).
func SetEvaluatorFactory(factory func() Evaluator) {
	evaluatorFactory = factory
}
