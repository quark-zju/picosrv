package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"picosrv/internal/config"
	"picosrv/internal/proxy"
	"picosrv/internal/systemd"
)

const (
	placeholderHMACSecret = "replace-with-long-random-secret"
	minHMACSecretLength   = 16
	defaultMaxHeaderBytes = 64 * 1024
)

func main() {
	var (
		certDir                  = flag.String("cert-dir", getenv("PICOSRV_CERT_DIR", ""), "tls cert directory (e.g. /etc/picosrv/certs)")
		secret                   = flag.String("hmac-secret", getenv("PICOSRV_HMAC_SECRET", ""), "hmac secret")
		reloadIntervalRaw        = flag.String("tls-reload-interval", getenv("PICOSRV_TLS_RELOAD_INTERVAL", "30s"), "certificate reload interval")
		responseHeaderTimeoutRaw = flag.String("proxy-response-header-timeout", getenv("PICOSRV_PROXY_RESPONSE_HEADER_TIMEOUT", "60s"), "timeout waiting for upstream response headers")
		webSocketIdleTimeoutRaw  = flag.String("websocket-idle-timeout", getenv("PICOSRV_WEBSOCKET_IDLE_TIMEOUT", "60s"), "timeout waiting for upstream websocket data")
		maxHeaderBytesRaw        = flag.String("max-header-bytes", getenv("PICOSRV_MAX_HEADER_BYTES", strconv.Itoa(defaultMaxHeaderBytes)), "maximum request header bytes")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if *secret == "" {
		exitErr(logger, errors.New("hmac secret is required (flag --hmac-secret or PICOSRV_HMAC_SECRET)"))
	}
	if err := validateHMACSecret(*secret); err != nil {
		exitErr(logger, err)
	}

	reloadInterval, err := time.ParseDuration(*reloadIntervalRaw)
	if err != nil {
		exitErr(logger, fmt.Errorf("invalid tls-reload-interval: %w", err))
	}
	responseHeaderTimeout, err := time.ParseDuration(*responseHeaderTimeoutRaw)
	if err != nil {
		exitErr(logger, fmt.Errorf("invalid proxy-response-header-timeout: %w", err))
	}
	webSocketIdleTimeout, err := time.ParseDuration(*webSocketIdleTimeoutRaw)
	if err != nil {
		exitErr(logger, fmt.Errorf("invalid websocket-idle-timeout: %w", err))
	}
	maxHeaderBytes, err := parsePositiveInt(*maxHeaderBytesRaw)
	if err != nil {
		exitErr(logger, fmt.Errorf("invalid max-header-bytes: %w", err))
	}

	srv, err := proxy.New(proxy.Options{
		Evaluator:                  config.NewEvaluator(),
		HMACSecret:                 *secret,
		CertDir:                    *certDir,
		TLSReloadInterval:          reloadInterval,
		ProxyResponseHeaderTimeout: responseHeaderTimeout,
		WebSocketIdleTimeout:       webSocketIdleTimeout,
		Logger:                     logger,
	})
	if err != nil {
		exitErr(logger, err)
	}

	listeners, err := systemd.Listeners()
	if err != nil {
		exitErr(logger, err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go srv.RunCertReloader(ctx)

	errCh := make(chan error, len(listeners))
	httpServers := make([]*http.Server, 0, len(listeners))

	for _, activated := range listeners {
		ln := activated.Listener
		isHTTPRedirect := shouldRedirectHTTP(ln)
		h := srv.Handler()
		if isHTTPRedirect {
			h = srv.RedirectHandler()
		}

		httpSrv := &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 5 * time.Second,
			MaxHeaderBytes:    maxHeaderBytes,
			ErrorLog:          slogErrorLog(logger),
		}
		httpServers = append(httpServers, httpSrv)

		go func(listener net.Listener, server *http.Server, useTLS bool) {
			if useTLS {
				tlsCfg := srv.TLSConfig()
				if tlsCfg == nil {
					errCh <- errors.New("tls listener configured but no cert dir provided")
					return
				}
				errCh <- server.Serve(tls.NewListener(listener, tlsCfg))
				return
			}
			errCh <- server.Serve(listener)
		}(ln, httpSrv, !isHTTPRedirect)
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			exitErr(logger, err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	for _, s := range httpServers {
		_ = s.Shutdown(shutdownCtx)
	}
	srv.CloseIdleConnections()
}

func shouldRedirectHTTP(ln net.Listener) bool {
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		return tcp.Port == 80
	}
	return false
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func validateHMACSecret(secret string) error {
	if secret == placeholderHMACSecret {
		return errors.New("hmac secret is still the default placeholder; generate a long random PICOSRV_HMAC_SECRET")
	}
	if len(secret) < minHMACSecretLength {
		return fmt.Errorf("hmac secret must be at least %d bytes", minHMACSecretLength)
	}
	return nil
}

func parsePositiveInt(raw string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if value <= 0 {
		return 0, errors.New("must be greater than zero")
	}
	return value, nil
}

func exitErr(logger *slog.Logger, err error) {
	logErr(logger, err)
	os.Exit(1)
}

func logErr(logger *slog.Logger, err error) {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	logger.Error("fatal error", "error", err)
}

func slogErrorLog(logger *slog.Logger) *log.Logger {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return slog.NewLogLogger(logger.Handler(), slog.LevelError)
}
