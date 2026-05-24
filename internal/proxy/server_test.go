package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"picosrv/internal/config"
)

type staticEvaluator struct {
	fn func(ctx config.Context, hasValidCookie bool) config.Decision
}

func (s staticEvaluator) Evaluate(ctx config.Context, _ *http.Request, hasValidCookie bool) config.Decision {
	return s.fn(ctx, hasValidCookie)
}

func TestDenyByDefault(t *testing.T) {
	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ bool) config.Decision {
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

func TestKnockCookieFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	srv, err := New(Options{
		Evaluator: staticEvaluator{fn: func(_ config.Context, hasValidCookie bool) config.Decision {
			if hasValidCookie {
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
		Evaluator: staticEvaluator{fn: func(_ config.Context, _ bool) config.Decision {
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
