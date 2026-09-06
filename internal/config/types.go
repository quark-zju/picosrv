package config

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// Password provides the SHA-256 hexadecimal representation used by Basic Auth.
type Password interface {
	SHA256Encoded() string
}

// PlainPassword identifies a password that should be hashed before comparison.
type PlainPassword string

func (p PlainPassword) SHA256Encoded() string {
	hash := sha256.Sum256([]byte(p))
	return hex.EncodeToString(hash[:])
}

// Sha256Encoded identifies a password that is already encoded as a SHA-256
// hexadecimal digest.
type Sha256Encoded string

func (p Sha256Encoded) SHA256Encoded() string { return string(p) }

type DecisionKind int

const (
	DecisionDeny DecisionKind = iota
	// DecisionAllowProxy forwards to a private backend while preserving the
	// original inbound Host header. Use this for normal site reverse proxying
	// where the backend expects the public virtual host. Request bodies stream
	// through without a global size limit; evaluators that buffer them must set
	// their own limit.
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

type CachePolicy int

const (
	// CachePolicyDefault leaves the response's cache headers unchanged.
	CachePolicyDefault CachePolicy = iota
	// CachePolicyImmutable marks successful responses as publicly cacheable for
	// one year. Callers should only use it for versioned or content-addressed
	// resources whose contents never change at the same URL.
	CachePolicyImmutable
)

type Decision struct {
	Kind DecisionKind
	// Upstream and RootDir should come from finite, administrator-controlled
	// configuration. Unbounded request-derived values grow cached handlers for
	// the lifetime of the process.
	Upstream string
	// UpstreamHost, when non-empty, overrides the Host header sent to an
	// internal proxy upstream. This is useful for loopback-bound applications
	// (such as dsh web) whose trusted-host checks require their local authority.
	// It does not affect the public Host used for policy evaluation.
	UpstreamHost string
	RootDir      string
	Reason       string
	RedirectPath string
	SetCookie    bool
	Realm        string
	CachePolicy  CachePolicy
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
	// cookie. To issue this cookie, an Evaluator can return a Decision such as
	// Decision{Kind: DecisionIssueCookieAndRedirect, SetCookie: true,
	// RedirectPath: "/"}.
	HasValidCookie() bool

	// ConsumeBasicAuth validates the request's HTTP Basic credentials against
	// user and password. Use PlainPassword for a plaintext password or
	// Sha256Encoded for an already encoded digest. On success it removes the
	// Authorization header so the credentials cannot be forwarded upstream.
	ConsumeBasicAuth(user string, password Password) bool
}

// EvaluationRequest contains the normalized request data and request-scoped
// capabilities available to an Evaluator.
type EvaluationRequest struct {
	Context Context
	HTTP    *http.Request
	Auth    RequestAuth
}

type Evaluator interface {
	// IsKnownHost reports whether host has a configured policy. Evaluate is not
	// called for requests whose host is unknown.
	IsKnownHost(host string) bool

	// Evaluate decides how to handle a request for a known host.
	Evaluate(req EvaluationRequest) Decision
}

var evaluatorFactory func() Evaluator

// SetEvaluatorFactory installs a process-local evaluator factory override.
// Intended for local customization via ignored files (e.g. custom_local.go).
func SetEvaluatorFactory(factory func() Evaluator) {
	evaluatorFactory = factory
}
