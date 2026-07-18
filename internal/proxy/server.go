package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"picosrv/internal/config"
)

const cookieName = "picosrv_knock"
const knockCookieTTL = 2 * 365 * 24 * time.Hour
const defaultWebSocketIdleTimeout = 60 * time.Second
const defaultWebSocketMaxConnections = 512
const immutableCacheControl = "public, max-age=31536000, immutable"

type Options struct {
	Evaluator                  config.Evaluator
	HMACSecret                 string
	CertDir                    string
	TLSReloadInterval          time.Duration
	ProxyResponseHeaderTimeout time.Duration
	WebSocketIdleTimeout       time.Duration
	WebSocketMaxConnections    int
	Logger                     *slog.Logger
	ProxyTransport             *http.Transport
}

type Server struct {
	evaluator   config.Evaluator
	cookieAuth  *cookieSigner
	logger      *slog.Logger
	proxyByHost sync.Map
	filesByRoot sync.Map
	transport   *http.Transport
	tlsState    *tlsCertState
	wsTimeout   time.Duration
	wsMaxConns  int64
	wsActive    atomic.Int64
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
		opts.ProxyTransport = defaultTransport(opts.ProxyResponseHeaderTimeout)
	}
	if opts.WebSocketIdleTimeout <= 0 {
		opts.WebSocketIdleTimeout = defaultWebSocketIdleTimeout
	}
	if opts.WebSocketMaxConnections <= 0 {
		opts.WebSocketMaxConnections = defaultWebSocketMaxConnections
	}

	s := &Server{
		evaluator:  opts.Evaluator,
		cookieAuth: newCookieSigner(opts.HMACSecret),
		logger:     opts.Logger,
		transport:  opts.ProxyTransport,
		wsTimeout:  opts.WebSocketIdleTimeout,
		wsMaxConns: int64(opts.WebSocketMaxConnections),
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

func (s *Server) CloseIdleConnections() {
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	s.filesByRoot.Range(func(_, value any) bool {
		_ = value.(*staticHandler).Close()
		return true
	})
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := stripDefaultPort(r.Host)
		if !s.evaluator.IsKnownHost(host) {
			http.NotFound(w, r)
			return
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := clientIPFromRemoteAddr(r.RemoteAddr)
	ctx := config.Context{Host: stripDefaultPort(r.Host), Path: r.URL.Path, UA: r.UserAgent(), Query: r.URL.Query()}
	decision := config.Decision{Kind: config.DecisionDeny, Reason: "unknown_host"}
	if s.evaluator.IsKnownHost(ctx.Host) {
		auth := &requestAuth{request: r, cookieAuth: s.cookieAuth, host: ctx.Host}
		decision = s.evaluator.Evaluate(config.EvaluationRequest{Context: ctx, HTTP: r, Auth: auth})
	}

	status := http.StatusNotFound
	upstream := ""
	wsUpgrade := isWebSocketUpgrade(r)

	switch decision.Kind {
	case config.DecisionRequireBasicAuth:
		realm := decision.Realm
		if realm == "" {
			realm = "picosrv"
		}
		w.Header().Set("WWW-Authenticate", "Basic realm="+strconv.Quote(realm))
		status = http.StatusUnauthorized
		http.Error(w, "unauthorized", status)
	case config.DecisionIssueCookieAndRedirect:
		if decision.SetCookie {
			value, err := s.cookieAuth.Issue(knockCookieTTL, ctx.Host)
			if err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     cookieName,
					Value:    value,
					Path:     "/",
					MaxAge:   int(knockCookieTTL.Seconds()),
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
			if !s.tryAcquireWebSocket() {
				status = http.StatusServiceUnavailable
				http.Error(w, "websocket capacity reached", status)
				break
			}
			defer s.releaseWebSocket()
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
		rw := newStatusCapture(w, decision.CachePolicy)
		proxy.ServeHTTP(rw, r)
		rw.finish()
		status = rw.status
	case config.DecisionAllowExternalProxy:
		upstream = decision.Upstream
		if wsUpgrade {
			status = http.StatusBadRequest
			http.Error(w, "websocket external proxy is not supported", status)
			break
		}
		proxy, err := s.externalProxyFor(decision.Upstream)
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, "bad gateway", status)
			s.logger.Error("build external proxy", "error", err)
			break
		}
		rw := newStatusCapture(w, decision.CachePolicy)
		proxy.ServeHTTP(rw, r)
		rw.finish()
		status = rw.status
	case config.DecisionAllowFiles:
		upstream = decision.RootDir
		handler, err := s.fileServerFor(decision.RootDir)
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, "bad gateway", status)
			s.logger.Error("build file server", "error", err, "root_dir", decision.RootDir)
			break
		}
		rw := newStatusCapture(w, decision.CachePolicy)
		handler.ServeHTTP(rw, r)
		rw.finish()
		status = rw.status
	default:
		status = http.StatusNotFound
		http.NotFound(w, r)
	}

	s.logger.Info("request",
		"client_ip", clientIP,
		"remote_addr", r.RemoteAddr,
		"method", r.Method,
		"host", ctx.Host,
		"path", ctx.Path,
		"status", status,
		"upstream", upstream,
		"latency_ms", time.Since(start).Milliseconds(),
		"decision_reason", decision.Reason,
		"ws_upgrade", wsUpgrade,
	)
}

func (s *Server) tryAcquireWebSocket() bool {
	for {
		active := s.wsActive.Load()
		if active >= s.wsMaxConns {
			return false
		}
		if s.wsActive.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func (s *Server) releaseWebSocket() {
	s.wsActive.Add(-1)
}

func (s *Server) proxyFor(target string) (*httputil.ReverseProxy, error) {
	return s.reverseProxyFor("internal:"+target, target, func(r *httputil.ProxyRequest, u *url.URL) {
		r.SetURL(u)
		r.Out.Host = stripDefaultPort(r.In.Host)
		clearUnsafeRequestHeaders(r.Out.Header)
		r.SetXForwarded()
	})
}

func (s *Server) externalProxyFor(target string) (*httputil.ReverseProxy, error) {
	return s.reverseProxyFor("external:"+target, target, func(r *httputil.ProxyRequest, u *url.URL) {
		r.SetURL(u)
		clearUnsafeRequestHeaders(r.Out.Header)
	})
}

func (s *Server) reverseProxyFor(cacheKey string, target string, rewrite func(*httputil.ProxyRequest, *url.URL)) (*httputil.ReverseProxy, error) {
	if proxy, ok := s.proxyByHost.Load(cacheKey); ok {
		return proxy.(*httputil.ReverseProxy), nil
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", target, err)
	}

	proxy := &httputil.ReverseProxy{
		Transport: s.transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			rewrite(r, u)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			s.logger.Error("reverse proxy error", "error", err, "host", r.Host, "path", r.URL.Path)
		},
	}

	actual, _ := s.proxyByHost.LoadOrStore(cacheKey, proxy)
	return actual.(*httputil.ReverseProxy), nil
}

func (s *Server) fileServerFor(rootDir string) (http.Handler, error) {
	if handler, ok := s.filesByRoot.Load(rootDir); ok {
		return handler.(*staticHandler).handler, nil
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("open root dir %q: %w", rootDir, err)
	}
	handler := &staticHandler{
		root:    root,
		handler: http.FileServerFS(root.FS()),
	}
	actual, loaded := s.filesByRoot.LoadOrStore(rootDir, handler)
	if loaded {
		_ = handler.Close()
		return actual.(*staticHandler).handler, nil
	}
	return handler.handler, nil
}

func (s *Server) proxyWebSocket(w http.ResponseWriter, r *http.Request, target string) (bool, error) {
	u, err := url.Parse(target)
	if err != nil {
		return false, err
	}
	switch u.Scheme {
	case "http", "ws":
	case "https", "wss":
		return false, fmt.Errorf("websocket upstream scheme %q is not supported", u.Scheme)
	default:
		return false, fmt.Errorf("unsupported websocket upstream scheme %q", u.Scheme)
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
	clone.Host = stripDefaultPort(r.Host)
	clearUnsafeRequestHeaders(clone.Header)
	clearForwardedHeaders(clone.Header)
	clearHopByHopRequestHeaders(clone.Header)
	clone.Header.Set("X-Forwarded-Host", stripDefaultPort(r.Host))
	clone.Header.Set("X-Forwarded-Proto", forwardedProto(r))
	clone.Header.Set("Upgrade", "websocket")
	clone.Header.Set("Connection", "upgrade")
	appendXForwardedFor(clone.Header, r.RemoteAddr)

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
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, copyErr := io.Copy(backendConn, clientRW)
		errc <- copyErr
	}()
	go func() {
		defer wg.Done()
		_, copyErr := copyWithReadIdleTimeout(clientConn, backendConn, s.wsTimeout)
		errc <- copyErr
	}()
	<-errc
	_ = backendConn.Close()
	_ = clientConn.Close()
	wg.Wait()
	return true, nil
}

func copyWithReadIdleTimeout(dst net.Conn, src net.Conn, timeout time.Duration) (int64, error) {
	if timeout <= 0 {
		return io.Copy(dst, src)
	}

	buf := make([]byte, 32*1024)
	var written int64
	for {
		if err := src.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return written, err
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			return written, er
		}
	}
}

func defaultTransport(responseHeaderTimeout time.Duration) *http.Transport {
	if responseHeaderTimeout <= 0 {
		responseHeaderTimeout = 60 * time.Second
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
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

func appendXForwardedFor(h http.Header, remoteAddr string) {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	if prior := h.Get("X-Forwarded-For"); prior != "" {
		h.Set("X-Forwarded-For", prior+", "+ip)
		return
	}
	h.Set("X-Forwarded-For", ip)
}

var unsafeRequestHeaderNames = map[string]struct{}{
	"forwarded":              {},
	"x-accel-redirect":       {},
	"x-client-ip":            {},
	"x-forwarded-for":        {},
	"x-forwarded-host":       {},
	"x-forwarded-port":       {},
	"x-forwarded-prefix":     {},
	"x-forwarded-proto":      {},
	"x-forwarded-scheme":     {},
	"x-forwarded-server":     {},
	"x-forwarded-ssl":        {},
	"x-http-method-override": {},
	"x-method-override":      {},
	"x-original-method":      {},
	"x-original-url":         {},
	"x-real-ip":              {},
	"x-rewrite-url":          {},
	"x-sendfile":             {},
}

var unsafeRequestHeaderPrefixes = []string{
	"x-auth-request-",
	"x-middleware-",
	"x-remote-",
}

func clearUnsafeRequestHeaders(h http.Header) {
	for k := range h {
		lk := strings.ToLower(k)
		if _, ok := unsafeRequestHeaderNames[lk]; ok || hasAnyPrefix(lk, unsafeRequestHeaderPrefixes) {
			h.Del(k)
		}
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func clearForwardedHeaders(h http.Header) {
	h.Del("X-Forwarded-For")
	h.Del("X-Forwarded-Host")
	h.Del("X-Forwarded-Proto")
}

var hopByHopRequestHeaderNames = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func clearHopByHopRequestHeaders(h http.Header) {
	for _, connection := range h.Values("Connection") {
		for _, token := range strings.Split(connection, ",") {
			if token = strings.TrimSpace(token); token != "" {
				h.Del(token)
			}
		}
	}
	for _, name := range hopByHopRequestHeaderNames {
		h.Del(name)
	}
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

func clientIPFromRemoteAddr(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(remoteAddr)
}

type statusCapture struct {
	http.ResponseWriter
	status      int
	cachePolicy config.CachePolicy
	wroteHeader bool
}

func newStatusCapture(w http.ResponseWriter, cachePolicy config.CachePolicy) *statusCapture {
	return &statusCapture{ResponseWriter: w, status: http.StatusOK, cachePolicy: cachePolicy}
}

func (s *statusCapture) Write(p []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(p)
}

func (s *statusCapture) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		s.ResponseWriter.WriteHeader(code)
		return
	}
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true
	s.status = code
	if s.cachePolicy == config.CachePolicyImmutable && isImmutableCacheStatus(code) {
		s.Header().Set("Cache-Control", immutableCacheControl)
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapture) Flush() {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *statusCapture) FlushError() error {
	type flushErrorer interface {
		FlushError() error
	}
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	if flusher, ok := s.ResponseWriter.(flushErrorer); ok {
		return flusher.FlushError()
	}
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
		return nil
	}
	return http.ErrNotSupported
}

func (s *statusCapture) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func (s *statusCapture) finish() {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
}

func isImmutableCacheStatus(code int) bool {
	return code >= 200 && code < 300 ||
		code == http.StatusNotModified ||
		code == http.StatusMovedPermanently ||
		code == http.StatusPermanentRedirect
}

type staticHandler struct {
	root    *os.Root
	handler http.Handler
}

func (h *staticHandler) Close() error {
	if h == nil || h.root == nil {
		return nil
	}
	return h.root.Close()
}

type cookiePayload struct {
	Exp  int64  `json:"exp"`
	Host string `json:"host"`
}

type cookieSigner struct {
	secret []byte
}

func newCookieSigner(secret string) *cookieSigner {
	return &cookieSigner{secret: []byte(secret)}
}

func (c *cookieSigner) Issue(ttl time.Duration, host string) (string, error) {
	payload := cookiePayload{Exp: time.Now().Add(ttl).Unix(), Host: host}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sig := c.sign(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *cookieSigner) Validate(cookie *http.Cookie, err error, host string) bool {
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
	return payload.Exp > time.Now().Unix() && payload.Host == host
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
	serverName := normalizeServerName(hello.ServerName)
	if serverName == "" {
		return nil, fmt.Errorf("invalid SNI server name %q", hello.ServerName)
	}
	candidates := certificateDomainCandidates(serverName)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("invalid SNI server name %q", hello.ServerName)
	}

	s.mu.RLock()
	for _, domain := range candidates {
		if rec, ok := s.certs[domain]; ok {
			s.mu.RUnlock()
			if err := rec.matchesServerName(serverName); err != nil {
				return nil, fmt.Errorf("certificate for domain %q does not cover %q: %w", domain, serverName, err)
			}
			return rec.cert, nil
		}
	}
	s.mu.RUnlock()

	var lastErr error
	for _, domain := range candidates {
		loaded, err := loadCertRecord(s.certDir, domain)
		if err != nil {
			lastErr = err
			continue
		}
		if err := loaded.matchesServerName(serverName); err != nil {
			return nil, fmt.Errorf("certificate for domain %q does not cover %q: %w", domain, serverName, err)
		}
		s.mu.Lock()
		s.certs[domain] = loaded
		s.mu.Unlock()
		return loaded.cert, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("load certificate for %q candidates %v: %w", serverName, candidates, lastErr)
	}
	return nil, fmt.Errorf("load certificate for %q candidates %v: no candidate domains", serverName, candidates)
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
				nextFiles, err := statCertFiles(s.certDir, domain)
				if err != nil {
					s.logger.Error("stat certificate", "domain", domain, "error", err)
					continue
				}
				s.mu.RLock()
				curr := s.certs[domain]
				unchanged := curr.files.Equal(nextFiles)
				s.mu.RUnlock()
				if unchanged {
					continue
				}

				next, err := loadCertRecord(s.certDir, domain)
				if err != nil {
					s.logger.Error("reload certificate", "domain", domain, "error", err)
					continue
				}
				s.mu.Lock()
				curr = s.certs[domain]
				if curr.hash != next.hash {
					s.certs[domain] = next
					reloaded++
				} else {
					curr.files = next.files
					s.certs[domain] = curr
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
	cert  *tls.Certificate
	leaf  *x509.Certificate
	files certFilesMeta
	hash  uint64
}

type certFilesMeta struct {
	fullchainModTime time.Time
	privkeyModTime   time.Time
}

func (m certFilesMeta) Equal(other certFilesMeta) bool {
	return m.fullchainModTime.Equal(other.fullchainModTime) && m.privkeyModTime.Equal(other.privkeyModTime)
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
	files, err := statCertFiles(certDir, domain)
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
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return certRecord{}, err
	}
	h := sha256.New()
	_, _ = h.Write(certPEM)
	_, _ = h.Write(keyPEM)
	sum := h.Sum(nil)
	hash := binary.BigEndian.Uint64(sum[:8])
	return certRecord{cert: &cert, leaf: leaf, files: files, hash: hash}, nil
}

func statCertFiles(certDir, domain string) (certFilesMeta, error) {
	fullchain, err := safeCertPath(certDir, domain, "fullchain.pem")
	if err != nil {
		return certFilesMeta{}, err
	}
	privkey, err := safeCertPath(certDir, domain, "privkey.pem")
	if err != nil {
		return certFilesMeta{}, err
	}
	fullchainInfo, err := os.Stat(fullchain)
	if err != nil {
		return certFilesMeta{}, err
	}
	privkeyInfo, err := os.Stat(privkey)
	if err != nil {
		return certFilesMeta{}, err
	}
	return certFilesMeta{
		fullchainModTime: fullchainInfo.ModTime(),
		privkeyModTime:   privkeyInfo.ModTime(),
	}, nil
}

func (r certRecord) matchesServerName(serverName string) error {
	if r.leaf == nil {
		return errors.New("missing parsed leaf certificate")
	}
	return r.leaf.VerifyHostname(serverName)
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

func certificateDomainCandidates(host string) []string {
	host = normalizeServerName(host)
	if net.ParseIP(host) != nil {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return nil
	}
	last := len(parts) - 2
	if len(parts) > 3 {
		last--
	}
	candidates := make([]string, 0, last+1)
	for i := 0; i <= last; i++ {
		candidates = append(candidates, strings.Join(parts[i:], "."))
	}
	return candidates
}

func normalizeServerName(host string) string {
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
	return host
}
