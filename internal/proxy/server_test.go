package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"picosrv/internal/config"
)

type staticEvaluator struct {
	fn func(ctx config.Context, hasValidCookie func() bool) config.Decision
}

func (s staticEvaluator) Evaluate(ctx config.Context, _ *http.Request, hasValidCookie func() bool) config.Decision {
	return s.fn(ctx, hasValidCookie)
}

func TestDenyByDefault(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
			return config.Decision{Kind: config.DecisionDeny, AllowReason: "policy"}
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

func TestCookieValidationIsLazy(t *testing.T) {
	calls := 0
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.Context, hasValidCookie func() bool) config.Decision {
			calls++
			// Deliberately never call hasValidCookie for this path.
			return config.Decision{Kind: config.DecisionDeny, AllowReason: "policy"}
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

func TestKnockCookieFlow(t *testing.T) {
	headersSeen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersSeen <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.Context, hasValidCookie func() bool) config.Decision {
			if hasValidCookie() {
				return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, AllowReason: "cookie"}
			}
			return config.Decision{Kind: config.DecisionIssueCookieAndRedirect, RedirectPath: "/", SetCookie: true, AllowReason: "knock"}
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

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/app", nil)
	req2.Host = "example.local"
	req2.AddCookie(knockCookie)
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
		if got := hdr.Get("x-middleware-subrequest"); got != "" {
			t.Fatalf("expected empty x-middleware-subrequest, got %q", got)
		}
		if hdr.Get("X-Forwarded-Host") == "" {
			t.Fatal("missing X-Forwarded-Host")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe upstream headers")
	}
}

func TestWebSocketTunnel(t *testing.T) {
	upgrader := websocket.Upgrader{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, AllowReason: "test"}
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
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
		}
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

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

func TestNormalizeTopLevelDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":      "example.com",
		"api.example.com":  "example.com",
		"api.example.com.": "example.com",
		"127.0.0.1":        "",
		"localhost":        "",
	}
	for in, want := range cases {
		got := normalizeTopLevelDomain(in)
		if got != want {
			t.Fatalf("normalizeTopLevelDomain(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTLSCertStateLookupByTopLevelDomain(t *testing.T) {
	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := generateSelfSignedCert("example.com")
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

func generateSelfSignedCert(commonName string) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{commonName},
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
