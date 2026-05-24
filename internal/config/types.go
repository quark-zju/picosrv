package config

import (
	"net/http"
)

type DecisionKind int

const (
	DecisionDeny DecisionKind = iota
	DecisionAllowProxy
	DecisionIssueCookieAndRedirect
)

type Decision struct {
	Kind         DecisionKind
	Upstream     string
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
	Evaluate(ctx Context, r *http.Request, hasValidCookie bool) Decision
}
