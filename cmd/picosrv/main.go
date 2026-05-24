package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"picosrv/internal/config"
	"picosrv/internal/proxy"
	"picosrv/internal/systemd"
)

func main() {
	var (
		certDir           = flag.String("cert-dir", getenv("PICOSRV_CERT_DIR", ""), "tls cert directory (e.g. /etc/letsencrypt/live)")
		secret            = flag.String("hmac-secret", getenv("PICOSRV_HMAC_SECRET", ""), "hmac secret")
		reloadIntervalRaw = flag.String("tls-reload-interval", getenv("PICOSRV_TLS_RELOAD_INTERVAL", "30s"), "certificate reload interval")
	)
	flag.Parse()

	if *secret == "" {
		exitErr(errors.New("hmac secret is required (flag --hmac-secret or PICOSRV_HMAC_SECRET)"))
	}

	reloadInterval, err := time.ParseDuration(*reloadIntervalRaw)
	if err != nil {
		exitErr(fmt.Errorf("invalid tls-reload-interval: %w", err))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	srv, err := proxy.New(proxy.Options{
		Evaluator:         config.NewEvaluator(),
		HMACSecret:        *secret,
		CertDir:           *certDir,
		TLSReloadInterval: reloadInterval,
		Logger:            logger,
	})
	if err != nil {
		exitErr(err)
	}

	listeners, err := systemd.Listeners()
	if err != nil {
		exitErr(err)
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

		httpSrv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
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
			exitErr(err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	for _, s := range httpServers {
		_ = s.Shutdown(shutdownCtx)
	}
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

func exitErr(err error) {
	_, _ = os.Stderr.WriteString(err.Error() + "\n")
	os.Exit(1)
}
