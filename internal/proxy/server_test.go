package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	fn func(ctx config.Context, hasValidCookie func() bool) config.Decision
}

func (s staticEvaluator) Evaluate(ctx config.Context, _ *http.Request, hasValidCookie func() bool) config.Decision {
	return s.fn(ctx, hasValidCookie)
}

type flushRecorder struct {
	http.ResponseWriter
	flushCalls      int
	flushErrorCalls int
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
	if knockCookie.MaxAge != int(knockCookieTTL.Seconds()) {
		t.Fatalf("knock cookie MaxAge = %d, want %d", knockCookie.MaxAge, int(knockCookieTTL.Seconds()))
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/app", nil)
	req2.Host = "example.local"
	req2.AddCookie(knockCookie)
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, AllowReason: "stream"}
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
			return config.Decision{Kind: config.DecisionAllowFiles, RootDir: tmpDir, AllowReason: "files"}
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
			return config.Decision{Kind: config.DecisionAllowFiles, RootDir: rootDir, AllowReason: "files"}
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: "http://" + backend.Addr().String(), AllowReason: "test"}
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: upstream.URL, AllowReason: "test"}
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ func() bool) config.Decision {
			return config.Decision{Kind: config.DecisionAllowProxy, Upstream: "wss://backend.example.local/ws", AllowReason: "test"}
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
		"a.b.example.co.uk":    {"a.b.example.co.uk", "b.example.co.uk", "example.co.uk", "co.uk"},
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
