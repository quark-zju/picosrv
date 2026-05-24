package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"picosrv/internal/config"
)

const cookieName = "picosrv_knock"
const knockCookieTTL = 2 * 365 * 24 * time.Hour

type Options struct {
	Evaluator         config.Evaluator
	HMACSecret        string
	CertDir           string
	TLSReloadInterval time.Duration
	Logger            *slog.Logger
	ProxyTransport    *http.Transport
}

type Server struct {
	evaluator   config.Evaluator
	cookieAuth  *cookieSigner
	logger      *slog.Logger
	proxyByHost sync.Map
	transport   *http.Transport
	tlsState    *tlsCertState
}

func New(opts Options) (*Server, error) {
	if opts.Evaluator == nil {
		return nil, errors.New("evaluator is required")
	}
	if opts.HMACSecret == "" {
		return nil, errors.New("HMAC secret is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	if opts.ProxyTransport == nil {
		opts.ProxyTransport = defaultTransport()
	}

	s := &Server{
		evaluator:  opts.Evaluator,
		cookieAuth: newCookieSigner(opts.HMACSecret),
		logger:     opts.Logger,
		transport:  opts.ProxyTransport,
	}

	if opts.CertDir != "" {
		reload := opts.TLSReloadInterval
		if reload <= 0 {
			reload = 30 * time.Second
		}
		state, err := newTLSCertState(opts.CertDir, reload, opts.Logger)
		if err != nil {
			return nil, err
		}
		s.tlsState = state
	}

	return s, nil
}

func (s *Server) TLSConfig() *tls.Config {
	if s.tlsState == nil {
		return nil
	}
	return &tls.Config{GetCertificate: s.tlsState.GetCertificate, MinVersion: tls.VersionTLS12}
}

func (s *Server) RunCertReloader(ctx context.Context) {
	if s.tlsState == nil {
		return
	}
	s.tlsState.Run(ctx)
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := stripDefaultPort(r.Host)
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := config.Context{Host: stripDefaultPort(r.Host), Path: r.URL.Path, UA: r.UserAgent(), Query: r.URL.Query()}
	hasValidCookie := s.cookieAuth.Validate(r.Cookie(cookieName))
	decision := s.evaluator.Evaluate(ctx, r, hasValidCookie)

	status := http.StatusNotFound
	upstream := ""
	wsUpgrade := isWebSocketUpgrade(r)

	switch decision.Kind {
	case config.DecisionIssueCookieAndRedirect:
		if decision.SetCookie {
			value, err := s.cookieAuth.Issue(knockCookieTTL)
			if err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     cookieName,
					Value:    value,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				s.logger.Error("issue cookie", "error", err)
			}
		}
		location := decision.RedirectPath
		if location == "" {
			location = "/"
		}
		status = http.StatusFound
		http.Redirect(w, r, location, status)
	case config.DecisionAllowProxy:
		upstream = decision.Upstream
		if wsUpgrade {
			hijacked, err := s.proxyWebSocket(w, r, decision.Upstream)
			if err != nil {
				status = http.StatusBadGateway
				if !hijacked {
					http.Error(w, "bad gateway", status)
				}
				s.logger.Error("websocket proxy failed", "error", err)
				break
			}
			status = http.StatusSwitchingProtocols
			break
		}
		proxy, err := s.proxyFor(decision.Upstream)
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, "bad gateway", status)
			s.logger.Error("build proxy", "error", err)
			break
		}
		rw := &statusCapture{ResponseWriter: w, status: http.StatusOK}
		proxy.ServeHTTP(rw, r)
		status = rw.status
	default:
		status = http.StatusNotFound
		http.NotFound(w, r)
	}

	s.logger.Info("request",
		"host", ctx.Host,
		"path", ctx.Path,
		"status", status,
		"upstream", upstream,
		"latency_ms", time.Since(start).Milliseconds(),
		"allow_reason", decision.AllowReason,
		"ws_upgrade", wsUpgrade,
	)
}

func (s *Server) proxyFor(target string) (*httputil.ReverseProxy, error) {
	if proxy, ok := s.proxyByHost.Load(target); ok {
		return proxy.(*httputil.ReverseProxy), nil
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", target, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = s.transport
	baseDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		baseDirector(r)
		r.Header.Set("X-Forwarded-Host", r.Host)
		r.Header.Set("X-Forwarded-Proto", forwardedProto(r))
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		s.logger.Error("reverse proxy error", "error", err, "host", r.Host, "path", r.URL.Path)
	}

	actual, _ := s.proxyByHost.LoadOrStore(target, proxy)
	return actual.(*httputil.ReverseProxy), nil
}

func (s *Server) proxyWebSocket(w http.ResponseWriter, r *http.Request, target string) (bool, error) {
	u, err := url.Parse(target)
	if err != nil {
		return false, err
	}
	backendConn, err := s.transport.DialContext(r.Context(), "tcp", u.Host)
	if err != nil {
		return false, err
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = backendConn.Close()
		return false, errors.New("response writer does not support hijack")
	}

	clientConn, clientRW, err := hj.Hijack()
	if err != nil {
		_ = backendConn.Close()
		return false, err
	}

	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = u.Host
	clone.Host = u.Host
	if clone.Header.Get("X-Forwarded-Host") == "" {
		clone.Header.Set("X-Forwarded-Host", r.Host)
	}
	clone.Header.Set("X-Forwarded-Proto", forwardedProto(r))

	if err := clone.Write(backendConn); err != nil {
		_ = writeRawBadGateway(clientConn)
		_ = backendConn.Close()
		_ = clientConn.Close()
		return true, err
	}

	if err := clientRW.Flush(); err != nil {
		_ = writeRawBadGateway(clientConn)
		_ = backendConn.Close()
		_ = clientConn.Close()
		return true, err
	}

	errc := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(backendConn, clientConn)
		errc <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(clientConn, backendConn)
		errc <- copyErr
	}()
	<-errc
	_ = backendConn.Close()
	_ = clientConn.Close()
	return true, nil
}

func defaultTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && headerContainsToken(r.Header, "Connection", "upgrade")
}

func headerContainsToken(h http.Header, key, token string) bool {
	for _, part := range h.Values(key) {
		for _, v := range strings.Split(part, ",") {
			if strings.EqualFold(strings.TrimSpace(v), token) {
				return true
			}
		}
	}
	return false
}

func forwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func stripDefaultPort(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	if port == "80" || port == "443" {
		return host
	}
	return hostport
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (s *statusCapture) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

type cookiePayload struct {
	Exp int64 `json:"exp"`
}

type cookieSigner struct {
	secret []byte
}

func newCookieSigner(secret string) *cookieSigner {
	return &cookieSigner{secret: []byte(secret)}
}

func (c *cookieSigner) Issue(ttl time.Duration) (string, error) {
	payload := cookiePayload{Exp: time.Now().Add(ttl).Unix()}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sig := c.sign(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *cookieSigner) Validate(cookie *http.Cookie, err error) bool {
	if err != nil || cookie == nil || cookie.Value == "" {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	expected := c.sign(body)
	if subtle.ConstantTimeCompare(expected, sig) != 1 {
		return false
	}
	var payload cookiePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Exp > time.Now().Unix()
}

func (c *cookieSigner) sign(b []byte) []byte {
	h := hmac.New(sha256.New, c.secret)
	_, _ = h.Write(b)
	return h.Sum(nil)
}

type tlsCertState struct {
	certDir  string
	interval time.Duration
	logger   *slog.Logger
	mu       sync.RWMutex
	certs    map[string]certRecord
}

func newTLSCertState(certDir string, interval time.Duration, logger *slog.Logger) (*tlsCertState, error) {
	s := &tlsCertState{
		certDir:  certDir,
		interval: interval,
		logger:   logger,
		certs:    make(map[string]certRecord),
	}
	return s, nil
}

func (s *tlsCertState) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil || hello.ServerName == "" {
		return nil, errors.New("missing SNI server name")
	}
	domain := normalizeTopLevelDomain(hello.ServerName)
	if domain == "" {
		return nil, fmt.Errorf("invalid SNI server name %q", hello.ServerName)
	}

	s.mu.RLock()
	rec, ok := s.certs[domain]
	s.mu.RUnlock()
	if !ok {
		loaded, err := loadCertRecord(s.certDir, domain)
		if err != nil {
			return nil, fmt.Errorf("load certificate for domain %q: %w", domain, err)
		}
		s.mu.Lock()
		s.certs[domain] = loaded
		s.mu.Unlock()
		return loaded.cert, nil
	}
	return rec.cert, nil
}

func (s *tlsCertState) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			domains := make([]string, 0, len(s.certs))
			for domain := range s.certs {
				domains = append(domains, domain)
			}
			s.mu.RUnlock()
			if len(domains) == 0 {
				continue
			}

			reloaded := 0
			for _, domain := range domains {
				next, err := loadCertRecord(s.certDir, domain)
				if err != nil {
					s.logger.Error("reload certificate", "domain", domain, "error", err)
					continue
				}
				s.mu.Lock()
				curr := s.certs[domain]
				if curr.hash != next.hash {
					s.certs[domain] = next
					reloaded++
				}
				s.mu.Unlock()
			}
			if reloaded > 0 {
				s.logger.Info("tls certificates reloaded", "reloaded", reloaded)
			}
		}
	}
}

type certRecord struct {
	cert *tls.Certificate
	hash uint64
}

func loadCertRecord(certDir, domain string) (certRecord, error) {
	fullchain, err := safeCertPath(certDir, domain, "fullchain.pem")
	if err != nil {
		return certRecord{}, err
	}
	privkey, err := safeCertPath(certDir, domain, "privkey.pem")
	if err != nil {
		return certRecord{}, err
	}
	certPEM, err := os.ReadFile(fullchain)
	if err != nil {
		return certRecord{}, err
	}
	keyPEM, err := os.ReadFile(privkey)
	if err != nil {
		return certRecord{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return certRecord{}, err
	}
	h := sha256.New()
	_, _ = h.Write(certPEM)
	_, _ = h.Write(keyPEM)
	sum := h.Sum(nil)
	hash := binary.BigEndian.Uint64(sum[:8])
	return certRecord{cert: &cert, hash: hash}, nil
}

func safeCertPath(certDir, domain, filename string) (string, error) {
	root := filepath.Clean(certDir)
	candidate := filepath.Clean(filepath.Join(root, domain, filename))
	if candidate != root && !strings.HasPrefix(candidate, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid certificate path for domain %q", domain)
	}
	return candidate, nil
}

func writeRawBadGateway(conn net.Conn) error {
	_, err := conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 11\r\n\r\nbad gateway"))
	return err
}

func normalizeTopLevelDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = strings.TrimSuffix(strings.ToLower(parsed), ".")
		}
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
