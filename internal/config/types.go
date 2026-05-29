package config

import (
	"net/http"
)

type DecisionKind int

const (
	DecisionDeny DecisionKind = iota
	DecisionAllowProxy
	DecisionAllowFiles
	DecisionIssueCookieAndRedirect
)

type Decision struct {
	Kind         DecisionKind
	Upstream     string
	RootDir      string
	AllowReason  string
	RedirectPath string
	SetCookie    bool
}

type Context struct {
	Host  string
	Path  string
	UA    string
	Query map[string][]string
}

type Evaluator interface {
	Evaluate(ctx Context, r *http.Request, hasValidCookie func() bool) Decision
}

type HostValidator interface {
	IsKnownHost(host string) bool
}

var evaluatorFactory func() Evaluator

// SetEvaluatorFactory installs a process-local evaluator factory override.
// Intended for local customization via ignored files (e.g. custom_local.go).
func SetEvaluatorFactory(factory func() Evaluator) {
	evaluatorFactory = factory
}
