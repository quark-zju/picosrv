package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"picosrv/internal/config"
)

type staticEvaluator struct {
	fn         func(req config.EvaluationRequest) config.Decision
	knownHosts map[string]bool
}

func (s staticEvaluator) Evaluate(req config.EvaluationRequest) config.Decision {
	return s.fn(req)
}

func (s staticEvaluator) IsKnownHost(host string) bool {
	if s.knownHosts == nil {
		return true
	}
	return s.knownHosts[host]
}

type flushRecorder struct {
	http.ResponseWriter
	flushCalls      int
	flushErrorCalls int
}

func TestDenyByDefault(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionDeny, Reason: "policy"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/x", nil)
	req.Host = "example.local"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAccessLogIncludesHTTPMetadata(t *testing.T) {
	var logs bytes.Buffer
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionRequireBasicAuth, Reason: "test"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://example.local/private", strings.NewReader("abc"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", strings.Repeat("a", maxLoggedUserAgentLength+10))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	wants := map[string]any{
		"http_protocol":         "HTTP/1.1",
		"request_content_type":  "application/json",
		"request_body_length":   float64(3),
		"response_content_type": "text/plain; charset=utf-8",
		"response_body_length":  float64(len("unauthorized\n")),
		"user_agent":            strings.Repeat("a", maxLoggedUserAgentLength-len(truncationMarker)) + truncationMarker,
	}
	for field, want := range wants {
		if got := entry[field]; got != want {
			t.Errorf("%s = %#v, want %#v", field, got, want)
		}
	}
}

func TestKnockRedirectDoesNotLeakCredential(t *testing.T) {
	var logs bytes.Buffer
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionIssueCookieAndRedirect, RedirectPath: "/", SetCookie: true, Reason: "knock"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.local/private-knock-token", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if got := entry["path"]; got != "[redacted]" {
		t.Errorf("logged path = %#v, want redacted", got)
	}
	if strings.Contains(logs.String(), "private-knock-token") {
		t.Fatal("knock credential appeared in access log")
	}
}

func TestBodyLengthAvailability(t *testing.T) {
	if got := knownLength(-1, false); got != nil {
		t.Fatalf("unknown request length = %#v, want nil", got)
	}

	rec := httptest.NewRecorder()
	capture := newStatusCapture(rec, config.CachePolicyDefault)
	capture.Flush()
	_, _ = capture.Write([]byte("streamed"))
	if got := knownLength(capture.bodyLength, !capture.hijacked); got != int64(len("streamed")) {
		t.Fatalf("completed streaming response length = %#v, want %d", got, len("streamed"))
	}
}

func TestBanMetadata(t *testing.T) {
	tests := []struct {
		name          string
		decision      config.Decision
		status        int
		wantCandidate bool
		wantReason    string
	}{
		{
			name:          "basic auth failure",
			decision:      config.Decision{Kind: config.DecisionRequireBasicAuth},
			status:        http.StatusUnauthorized,
			wantCandidate: true,
			wantReason:    "basic_auth_failed",
		},
		{
			name:          "local policy denial",
			decision:      config.Decision{Kind: config.DecisionDeny},
			status:        http.StatusNotFound,
			wantCandidate: true,
			wantReason:    "policy_denied",
		},
		{
			name:          "private upstream auth failure",
			decision:      config.Decision{Kind: config.DecisionAllowProxy},
			status:        http.StatusUnauthorized,
			wantCandidate: true,
			wantReason:    "upstream_basic_auth_failed",
		},
		{
			name:          "external upstream auth failure",
			decision:      config.Decision{Kind: config.DecisionAllowExternalProxy},
			status:        http.StatusUnauthorized,
			wantCandidate: true,
			wantReason:    "upstream_basic_auth_failed",
		},
		{
			name:     "upstream forbidden",
			decision: config.Decision{Kind: config.DecisionAllowProxy},
			status:   http.StatusForbidden,
		},
		{
			name:     "upstream not found",
			decision: config.Decision{Kind: config.DecisionAllowProxy},
			status:   http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate, reason := banMetadata(tt.decision, tt.status)
			if candidate != tt.wantCandidate || reason != tt.wantReason {
				t.Fatalf("ban metadata = (%v, %q), want (%v, %q)", candidate, reason, tt.wantCandidate, tt.wantReason)
			}
		})
	}
}

func TestTLSConfigHTTP2(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		want    []string
	}{
		{name: "disabled", want: nil},
		{name: "enabled", enabled: true, want: []string{"h2", "http/1.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &Server{tlsState: &tlsCertState{}, enableHTTP2: tt.enabled}
			if got := srv.TLSConfig().NextProtos; !slices.Equal(got, tt.want) {
				t.Fatalf("NextProtos = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxyAppliesImmutableCachePolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("versioned asset"))
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{
				Kind:        config.DecisionAllowProxy,
				Upstream:    upstream.URL,
				Reason:      "immutable_asset",
				CachePolicy: config.CachePolicyImmutable,
			}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.CloseIdleConnections()

	req := httptest.NewRequest(http.MethodGet, "http://foo/asserts/app.js", nil)
	req.Host = "foo"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != immutableCacheControl {
		t.Fatalf("unexpected Cache-Control %q", got)
	}
}

func TestImmutableCachePolicyStatuses(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{status: http.StatusOK, want: true},
		{status: http.StatusPartialContent, want: true},
		{status: http.StatusNoContent, want: true},
		{status: http.StatusMovedPermanently, want: true},
		{status: http.StatusFound, want: false},
		{status: http.StatusNotModified, want: true},
		{status: http.StatusTemporaryRedirect, want: false},
		{status: http.StatusPermanentRedirect, want: true},
		{status: http.StatusNotFound, want: false},
		{status: http.StatusInternalServerError, want: false},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Cache-Control", "no-store")
			capture := newStatusCapture(rec, config.CachePolicyImmutable)
			capture.WriteHeader(tt.status)

			got := rec.Header().Get("Cache-Control")
			if tt.want && got != immutableCacheControl {
				t.Fatalf("expected immutable Cache-Control, got %q", got)
			}
			if !tt.want && got != "no-store" {
				t.Fatalf("expected original Cache-Control, got %q", got)
			}
		})
	}
}

func TestImmutableCachePolicyHandlesImplicitOK(t *testing.T) {
	tests := []struct {
		name string
		act  func(*statusCapture)
	}{
		{name: "write", act: func(w *statusCapture) { _, _ = w.Write([]byte("body")) }},
		{name: "flush", act: func(w *statusCapture) { w.Flush() }},
		{name: "empty", act: func(w *statusCapture) { w.finish() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			capture := newStatusCapture(rec, config.CachePolicyImmutable)
			tt.act(capture)

			if got := rec.Header().Get("Cache-Control"); got != immutableCacheControl {
				t.Fatalf("unexpected Cache-Control %q", got)
			}
			if capture.status != http.StatusOK {
				t.Fatalf("expected captured 200, got %d", capture.status)
			}
		})
	}
}

func TestUnknownHostSkipsEvaluation(t *testing.T) {
	evaluationCalls := 0
	srv, err := New(Options{
		Evaluator: staticEvaluator{
			fn: func(_ config.EvaluationRequest) config.Decision {
				evaluationCalls++
				return config.Decision{Kind: config.DecisionAllowFiles, RootDir: t.TempDir(), Reason: "unexpected"}
			},
			knownHosts: map[string]bool{"example.local": true},
		},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://unknown.local/private", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if evaluationCalls != 0 {
		t.Fatalf("expected evaluator not to run, got %d calls", evaluationCalls)
	}
}

func TestRequestHostIsNormalizedBeforeEvaluation(t *testing.T) {
	var evaluatedHost string
	srv, err := New(Options{
		Evaluator: staticEvaluator{
			fn: func(req config.EvaluationRequest) config.Decision {
				evaluatedHost = req.Context.Host
				return config.Decision{Kind: config.DecisionDeny, Reason: "test"}
			},
			knownHosts: map[string]bool{"example.local": true},
		},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.local/private", nil)
	req.Host = "EXAMPLE.LOCAL.:443"
	srv.Handler().ServeHTTP(rec, req)

	if evaluatedHost != "example.local" {
		t.Fatalf("evaluated Host = %q", evaluatedHost)
	}
}

func TestRequireBasicAuthChallengesClient(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionRequireBasicAuth, Realm: "private site", Reason: "basic_auth"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.local/private", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="private site"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestBasicAuthCredentialsAreNotForwarded(t *testing.T) {
	upstreamAuthorization := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthorization <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(req config.EvaluationRequest) config.Decision {
			if !req.Auth.ConsumeBasicAuth("alice", "secret") {
				return config.Decision{Kind: config.DecisionRequireBasicAuth, Realm: "private", Reason: "basic_auth"}
			}
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, Reason: "basic_auth"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.local/private", nil)
	req.SetBasicAuth("alice", "secret")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if got := <-upstreamAuthorization; got != "" {
		t.Fatalf("upstream Authorization = %q", got)
	}
}

func TestCookieValidationIsLazy(t *testing.T) {
	calls := 0
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(req config.EvaluationRequest) config.Decision {
			calls++
			// Deliberately never call hasValidCookie for this path.
			return config.Decision{Kind: config.DecisionDeny, Reason: "policy"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/x", nil)
	req.Host = "example.local"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	if calls != 1 {
		t.Fatalf("expected evaluator to run once, got %d", calls)
	}
}

func TestRedirectHandlerRejectsUnknownHost(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{
			fn: func(_ config.EvaluationRequest) config.Decision {
				t.Fatal("redirect handler must not evaluate request policy")
				return config.Decision{Kind: config.DecisionDeny, Reason: "policy"}
			},
			knownHosts: map[string]bool{"example.local": true},
		},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://evil.local/path?q=1", nil)
	req.Host = "evil.local"
	rec := httptest.NewRecorder()

	srv.RedirectHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestRedirectHandlerAllowsKnownHost(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{
			fn: func(_ config.EvaluationRequest) config.Decision {
				t.Fatal("redirect handler must not evaluate request policy")
				return config.Decision{Kind: config.DecisionDeny, Reason: "policy"}
			},
			knownHosts: map[string]bool{"example.local": true},
		},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.local/path?q=1", nil)
	req.Host = "EXAMPLE.LOCAL.:80"
	rec := httptest.NewRecorder()

	srv.RedirectHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("expected 301, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://example.local/path?q=1" {
		t.Fatalf("Location = %q", got)
	}
}

func TestKnockCookieFlow(t *testing.T) {
	headersSeen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersSeen <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(req config.EvaluationRequest) config.Decision {
			if req.Auth.HasValidCookie() {
				return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, Reason: "cookie"}
			}
			return config.Decision{Kind: config.DecisionIssueCookieAndRedirect, RedirectPath: "/", SetCookie: true, Reason: "knock"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/knock", nil)
	req.Host = "example.local"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	var knockCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			knockCookie = c
			break
		}
	}
	if knockCookie == nil {
		t.Fatal("missing knock cookie")
	}
	if knockCookie.MaxAge != int(knockCookieTTL.Seconds()) {
		t.Fatalf("knock cookie MaxAge = %d, want %d", knockCookie.MaxAge, int(knockCookieTTL.Seconds()))
	}

	crossHostReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/app", nil)
	crossHostReq.Host = "other.example.local"
	crossHostReq.AddCookie(knockCookie)
	crossHostResp, err := client.Do(crossHostReq)
	if err != nil {
		t.Fatal(err)
	}
	defer crossHostResp.Body.Close()
	if crossHostResp.StatusCode != http.StatusFound {
		t.Fatalf("expected cross-host cookie reuse to miss auth and redirect, got %d", crossHostResp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/app", nil)
	req2.Host = "example.local"
	req2.AddCookie(knockCookie)
	req2.AddCookie(&http.Cookie{Name: "app_session", Value: "app-secret"})
	req2.Header.Set("X-Test-Compat", "should-be-forwarded")
	req2.Header.Set("X-Middleware-Subrequest", "should-be-removed")
	req2.Header.Set("X-Forwarded-For", "198.51.100.9")
	req2.Header.Set("Forwarded", "for=198.51.100.9;proto=https")
	req2.Header.Set("X-Real-IP", "198.51.100.9")
	req2.Header.Set("X-Original-URL", "/admin")
	req2.Header.Set("X-Rewrite-URL", "/admin")
	req2.Header.Set("X-Forwarded-Prefix", "/internal")
	req2.Header.Set("X-HTTP-Method-Override", "DELETE")
	req2.Header.Set("X-Accel-Redirect", "/private")
	req2.Header.Set("X-Sendfile", "/private/file")
	req2.Header.Set("X-Remote-User", "admin")
	req2.Header.Set("X-Auth-Request-User", "admin")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
	select {
	case hdr := <-headersSeen:
		if got := hdr.Get("Cookie"); got != "app_session=app-secret" {
			t.Fatalf("Cookie = %q, want only the application cookie", got)
		}
		if got := hdr.Get("X-Middleware-Subrequest"); got != "" {
			t.Fatalf("expected empty x-middleware-subrequest, got %q", got)
		}
		for _, name := range []string{
			"Forwarded",
			"X-Real-IP",
			"X-Original-URL",
			"X-Rewrite-URL",
			"X-Forwarded-Prefix",
			"X-HTTP-Method-Override",
			"X-Accel-Redirect",
			"X-Sendfile",
			"X-Remote-User",
			"X-Auth-Request-User",
		} {
			if got := hdr.Get(name); got != "" {
				t.Fatalf("expected %s to be removed, got %q", name, got)
			}
		}
		if got := hdr.Get("X-Test-Compat"); got != "should-be-forwarded" {
			t.Fatalf("expected X-Test-Compat to be forwarded, got %q", got)
		}
		if hdr.Get("X-Forwarded-Host") == "" {
			t.Fatal("missing X-Forwarded-Host")
		}
		if got := hdr.Values("X-Forwarded-For"); len(got) != 1 || strings.Contains(got[0], "198.51.100.9") {
			t.Fatalf("expected proxy-generated X-Forwarded-For only, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe upstream headers")
	}
}

func TestAllowProxyPreservesInboundHost(t *testing.T) {
	hostSeen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostSeen <- r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, Reason: "test"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.CloseIdleConnections()

	proxyServer := httptest.NewServer(srv.Handler())
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/v1/chat/completions", nil)
	req.Host = "private.example.local"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	select {
	case got := <-hostSeen:
		if got != "private.example.local" {
			t.Fatalf("upstream Host = %q, want inbound host", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe upstream request")
	}
}

func TestAllowExternalProxyUsesUpstreamHostAndForwardsRequest(t *testing.T) {
	type observedRequest struct {
		host          string
		path          string
		rawQuery      string
		authorization string
		headers       http.Header
	}
	seen := make(chan observedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observedRequest{
			host:          r.Host,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"),
			headers:       r.Header.Clone(),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowExternalProxy, Upstream: upstream.URL, Reason: "test"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.CloseIdleConnections()

	proxyServer := httptest.NewServer(srv.Handler())
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/v1/chat/completions?model=gpt-4.1&stream=true", strings.NewReader("{}"))
	req.Host = "llm-lan.example.com"
	req.Header.Set("Authorization", "Bearer upstream-key")
	req.Header.Set("Cookie", "picosrv_knock=gateway-secret")
	req.Header.Set("Proxy-Authorization", "Basic proxy-secret")
	req.Header.Set("X-Forwarded-Host", "llm-lan.example.com")
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	select {
	case got := <-seen:
		if got.host != upstreamURL.Host {
			t.Fatalf("upstream Host = %q, want %q", got.host, upstreamURL.Host)
		}
		if got.path != "/v1/chat/completions" {
			t.Fatalf("path = %q", got.path)
		}
		if got.rawQuery != "model=gpt-4.1&stream=true" {
			t.Fatalf("raw query = %q", got.rawQuery)
		}
		if got.authorization != "Bearer upstream-key" {
			t.Fatalf("Authorization = %q", got.authorization)
		}
		for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Forwarded-Host", "X-Forwarded-For", "X-Forwarded-Proto"} {
			if value := got.headers.Get(name); value != "" {
				t.Fatalf("expected %s to be empty, got %q", name, value)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe upstream request")
	}
}

func TestAllowExternalProxyRejectsWebSocketUpgrade(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowExternalProxy, Upstream: "http://127.0.0.1:1", Reason: "test"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(srv.Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws://" + proxyURL.Host + "/v1/realtime"

	hdr := http.Header{}
	hdr.Set("Host", "llm-lan.example.com")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err == nil {
		conn.Close()
		t.Fatal("expected websocket dial to fail")
	}
	if resp == nil {
		t.Fatalf("expected 400 response, got dial error without response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestProxyStreamsServerSentEvents(t *testing.T) {
	const chunkCount = 4

	type writeEvent struct {
		chunk int
		at    time.Time
	}

	upstreamWriteAt := make(chan writeEvent, chunkCount)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("response writer does not support flushing")
		}

		w.Header().Set("Content-Type", "text/event-stream")
		for i := 1; i <= chunkCount; i++ {
			if _, err := w.Write([]byte("data: chunk-" + string(rune('0'+i)) + "\n\n")); err != nil {
				t.Fatalf("write chunk %d: %v", i, err)
			}
			flusher.Flush()
			upstreamWriteAt <- writeEvent{chunk: i, at: time.Now()}
			if i < chunkCount {
				time.Sleep(120 * time.Millisecond)
			}
		}
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, Reason: "stream"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.CloseIdleConnections()

	proxyServer := httptest.NewServer(srv.Handler())
	defer proxyServer.Close()

	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/stream", nil)
	req.Host = "stream.example.local"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	var nextWrite *writeEvent
	for i := 1; i <= chunkCount; i++ {
		chunk, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read chunk %d: %v", i, err)
		}
		readAt := time.Now()
		currentWrite := nextWrite
		if currentWrite == nil {
			event := <-upstreamWriteAt
			currentWrite = &event
		}
		nextWrite = nil

		want := "data: chunk-" + string(rune('0'+i)) + "\n"
		if chunk != want {
			t.Fatalf("unexpected chunk %d: got %q want %q", i, chunk, want)
		}
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("read event separator %d: %v", i, err)
		}
		if currentWrite.chunk != i {
			t.Fatalf("out-of-order write event: got chunk %d want %d", currentWrite.chunk, i)
		}
		if delay := readAt.Sub(currentWrite.at); delay > 90*time.Millisecond {
			t.Fatalf("chunk %d was not forwarded promptly, delay=%v", i, delay)
		}
		if i < chunkCount {
			event := <-upstreamWriteAt
			if !readAt.Before(event.at) {
				t.Fatalf("chunk %d arrived too late: read at %v, next chunk written at %v", i, readAt, event.at)
			}
			nextWrite = &event
		}
	}
}

func TestProxyUsesDefaultFlushInterval(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionDeny}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := srv.proxyFor("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if proxy.FlushInterval != 0 {
		t.Fatalf("expected default flush interval, got %v", proxy.FlushInterval)
	}
}

func TestStatusCaptureSupportsResponseControllerFlush(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &flushRecorder{ResponseWriter: recorder}
	capture := &statusCapture{ResponseWriter: writer, status: http.StatusOK}

	controller := http.NewResponseController(capture)
	if err := controller.Flush(); err != nil {
		t.Fatalf("flush via response controller: %v", err)
	}
	if writer.flushErrorCalls != 1 {
		t.Fatalf("expected FlushError to be used once, got %d", writer.flushErrorCalls)
	}
	if writer.flushCalls != 0 {
		t.Fatalf("expected Flush fallback not to be used, got %d", writer.flushCalls)
	}
}

func (f *flushRecorder) Header() http.Header {
	return f.ResponseWriter.Header()
}

func (f *flushRecorder) Write(p []byte) (int, error) {
	return f.ResponseWriter.Write(p)
}

func (f *flushRecorder) WriteHeader(statusCode int) {
	f.ResponseWriter.WriteHeader(statusCode)
}

func (f *flushRecorder) Flush() {
	f.flushCalls++
}

func (f *flushRecorder) FlushError() error {
	f.flushErrorCalls++
	return nil
}

func TestStaticFileServing(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowFiles, RootDir: tmpDir, Reason: "files"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.CloseIdleConnections()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/hello.txt", nil)
	req.Host = "static.example.local"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "hello" {
		t.Fatalf("unexpected body %q", string(body))
	}
}

func TestStaticFileServingRejectsParentTraversal(t *testing.T) {
	parentDir := t.TempDir()
	rootDir := filepath.Join(parentDir, "public")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parentDir, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowFiles, RootDir: rootDir, Reason: "files"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.CloseIdleConnections()

	req := httptest.NewRequest(http.MethodGet, "http://static.example.local/../secret.txt", nil)
	req.Host = "static.example.local"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("unexpected secret leak")
	}
}

func TestWebSocketTunnel(t *testing.T) {
	upgrader := websocket.Upgrader{}
	headersSeen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
		headersSeen <- r.Header.Clone()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.WriteMessage(mt, append([]byte("echo:"), msg...))
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, Reason: "test"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(srv.Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws://" + strings.TrimPrefix(proxyURL.Host, "http://") + "/ws"

	hdr := http.Header{}
	hdr.Set("Host", "example.local")
	hdr.Set("Cookie", cookieName+"=gateway-secret; app_session=app-secret")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
		}
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()
	select {
	case got := <-headersSeen:
		if cookie := got.Get("Cookie"); cookie != "app_session=app-secret" {
			t.Fatalf("Cookie = %q, want only the application cookie", cookie)
		}
	case <-time.After(time.Second):
		t.Fatal("did not observe upstream websocket request")
	}

	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "echo:ping" {
		t.Fatalf("unexpected msg: %s", msg)
	}
}

func TestWebSocketUpgradeRequiresGet(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.local/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if isWebSocketUpgrade(req) {
		t.Fatal("POST must not enter the WebSocket hijack path")
	}
}

func TestWebSocketUpstreamAddressAddsDefaultPort(t *testing.T) {
	u, err := url.Parse("http://backend.example.local/ws")
	if err != nil {
		t.Fatal(err)
	}
	got, err := websocketUpstreamAddress(u)
	if err != nil {
		t.Fatal(err)
	}
	if got != "backend.example.local:80" {
		t.Fatalf("upstream address = %q", got)
	}
}

func TestWebSocketDrainsHijackBufferedClientData(t *testing.T) {
	const bufferedData = "buffered-client-data"

	gotData := make(chan string, 1)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				gotData <- ""
				return
			}
			if line == "\r\n" {
				break
			}
		}
		buf := make([]byte, len(bufferedData))
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			gotData <- ""
			return
		}
		gotData <- string(buf)
	}()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: "http://" + backend.Addr().String(), Reason: "test"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(srv.Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	request := "GET /ws HTTP/1.1\r\n" +
		"Host: example.local\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"\r\n" +
		bufferedData
	if _, err := clientConn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-gotData:
		if got != bufferedData {
			t.Fatalf("backend read buffered data %q, want %q", got, bufferedData)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive hijack-buffered client data")
	}
}

func TestClearHopByHopRequestHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive, X-Remove-Me")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic secret")
	h.Set("Proxy-Authenticate", "Basic")
	h.Set("TE", "trailers")
	h.Set("Trailer", "Expires")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "websocket")
	h.Set("X-Remove-Me", "connection-token")
	h.Set("X-Keep-Me", "end-to-end")

	clearHopByHopRequestHeaders(h)

	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authorization",
		"Proxy-Authenticate",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"X-Remove-Me",
	} {
		if got := h.Get(name); got != "" {
			t.Fatalf("expected %s to be removed, got %q", name, got)
		}
	}
	if got := h.Get("X-Keep-Me"); got != "end-to-end" {
		t.Fatalf("expected X-Keep-Me to remain, got %q", got)
	}
}

func TestWebSocketUpstreamIdleTimeout(t *testing.T) {
	upgrader := websocket.Upgrader{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(250 * time.Millisecond)
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, Reason: "test"}
		}},
		HMACSecret:           "secret",
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		WebSocketIdleTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(srv.Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws://" + proxyURL.Host + "/ws"

	hdr := http.Header{}
	hdr.Set("Host", "example.local")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
		}
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected websocket read to fail after upstream idle timeout")
	}
}

func TestWebSocketRejectsSecureUpstream(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.EvaluationRequest) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: "wss://backend.example.local/ws", Reason: "test"}
		}},
		HMACSecret: "secret",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(srv.Handler())
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL := "ws://" + proxyURL.Host + "/ws"

	hdr := http.Header{}
	hdr.Set("Host", "example.local")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err == nil {
		conn.Close()
		t.Fatal("expected websocket dial to fail")
	}
	if resp == nil {
		t.Fatalf("expected 502 response, got dial error without response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

func TestCertificateDomainCandidates(t *testing.T) {
	cases := map[string][]string{
		"example.com":          {"example.com"},
		"api.example.com":      {"api.example.com", "example.com"},
		"api.example.com.":     {"api.example.com", "example.com"},
		"a.b.example.co.uk":    {"a.b.example.co.uk", "b.example.co.uk", "example.co.uk"},
		"127.0.0.1":            nil,
		"localhost":            nil,
		"api.example.com:8443": {"api.example.com", "example.com"},
		"[2001:db8::1]:443":    nil,
		"2001:db8::1":          nil,
	}
	for in, want := range cases {
		got := certificateDomainCandidates(in)
		if !slices.Equal(got, want) {
			t.Fatalf("certificateDomainCandidates(%q)=%v want %v", in, got, want)
		}
	}
}

func TestClientIPFromRemoteAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:44321":  "203.0.113.7",
		"[2001:db8::1]:9443": "2001:db8::1",
		"203.0.113.7":        "203.0.113.7",
		"":                   "",
	}
	for in, want := range cases {
		got := clientIPFromRemoteAddr(in)
		if got != want {
			t.Fatalf("clientIPFromRemoteAddr(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTLSCertStateLookupByParentDomain(t *testing.T) {
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"example.com", "*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	state, err := newTLSCertState(tmpDir, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := state.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected certificate bytes")
	}
}

func TestTLSCertStateLookupByParentDomainCandidate(t *testing.T) {
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.co.uk")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"example.co.uk", "*.example.co.uk"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	state, err := newTLSCertState(tmpDir, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := state.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.co.uk"})
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected certificate bytes")
	}
}

func TestTLSCertStateRejectsRootDomainForWildcardOnlyCert(t *testing.T) {
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	state, err := newTLSCertState(tmpDir, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Fatal("expected root domain lookup to fail for wildcard-only cert")
	}
}

func TestTLSCertStateAllowsSubdomainForWildcardOnlyCert(t *testing.T) {
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := generateSelfSignedCert([]string{"*.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "fullchain.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "privkey.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	state, err := newTLSCertState(tmpDir, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := state.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected certificate bytes")
	}
}

func TestTLSCertStateReloadChecksMTimeBeforeHash(t *testing.T) {
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fullchainPath := filepath.Join(domainDir, "fullchain.pem")
	privkeyPath := filepath.Join(domainDir, "privkey.pem")
	firstCertPEM, firstKeyPEM, err := generateSelfSignedCert([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	secondCertPEM, secondKeyPEM, err := generateSelfSignedCert([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	secondParsed, err := tls.X509KeyPair(secondCertPEM, secondKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullchainPath, firstCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privkeyPath, firstKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	initialTime := time.Now().Add(-time.Hour).Round(time.Second)
	if err := os.Chtimes(fullchainPath, initialTime, initialTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(privkeyPath, initialTime, initialTime); err != nil {
		t.Fatal(err)
	}

	state, err := newTLSCertState(tmpDir, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	firstCert, err := state.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(fullchainPath, secondCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privkeyPath, secondKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fullchainPath, initialTime, initialTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(privkeyPath, initialTime, initialTime); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go state.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	unchangedCert, err := state.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(unchangedCert.Certificate[0], firstCert.Certificate[0]) {
		t.Fatal("expected certificate to stay cached when content changes without mtime change")
	}

	nextTime := initialTime.Add(2 * time.Second)
	if err := os.Chtimes(fullchainPath, nextTime, nextTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(privkeyPath, nextTime, nextTime); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		reloadedCert, err := state.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if slices.Equal(reloadedCert.Certificate[0], secondParsed.Certificate[0]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected certificate reload after mtime change")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func generateSelfSignedCert(dnsNames []string) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	if len(dnsNames) == 0 {
		return nil, nil, errors.New("at least one DNS name is required")
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM, nil
}
