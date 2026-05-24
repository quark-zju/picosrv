# picosrv v1

## Summary

picosrv v1 is a low-memory reverse proxy built with Go standard library components. It uses systemd socket activation, host-based upstream routing, websocket support, knock-cookie access control, and TLS certificate hot reload from files managed by acme.sh or letsencrypt.

## Runtime Model

- Listener source: systemd socket activation only (`LISTEN_PID`, `LISTEN_FDS`).
- Default socket behavior: listen on TCP 443 only (HTTPS-only).
- Optional redirect behavior: if operator enables TCP port 80 listener, requests return `301` redirect to HTTPS.
- Other listeners serve proxy traffic. If TLS cert and key are configured, the listener is wrapped with TLS.
- The process does not bind ports directly.

## Policy Model

Access policy is implemented in Go code through an evaluator:

- Input: host, path, user-agent, query, cookie validity.
- Output:
  - `AllowProxy(upstream)`
  - `IssueCookieAndRedirect("/")`
  - `Deny404`

Default behavior is deny-by-default. You can customize behavior with build tags:

- default policy file: `//go:build !custom`
- local policy file: `//go:build custom`
- build custom binary: `go build -tags custom ./cmd/picosrv`

## Security and Cookie

- Knock cookie is signed with HMAC-SHA256.
- Secret is required and only provided by CLI/ENV.
- Missing secret causes startup failure.
- Cookie attributes: `HttpOnly`, `Secure`, `SameSite=Lax`.

## TLS and Cert Reload

- Cert directory is provided by CLI/ENV (letsencrypt live layout).
- Certificate lookup uses SNI top-level domain (last two labels).
- Files are loaded from `<cert-dir>/<domain>/fullchain.pem` and `<cert-dir>/<domain>/privkey.pem`.
- Certificates are polled on interval and swapped for new handshakes.
- Existing connections are not interrupted.

## Upstream Transport Defaults

- Dial timeout: 3s
- TLS handshake timeout: 3s
- Response header timeout: 10s
- Idle conn timeout: 90s
- Max idle conns: 100
- Max idle conns per host: 16

These defaults prevent stuck upstreams from consuming workers indefinitely.

## Logging

Structured JSON logs go to stdout/stderr and are expected to be collected by journald.

Fields:

- `host`
- `path`
- `status`
- `upstream`
- `latency_ms`
- `allow_reason`
- `ws_upgrade`

## CLI / ENV

- `--hmac-secret` / `PICOSRV_HMAC_SECRET` (required)
- `--cert-dir` / `PICOSRV_CERT_DIR`
- `--tls-reload-interval` / `PICOSRV_TLS_RELOAD_INTERVAL` (default `30s`)

## Test Coverage

Current tests include:

- deny-by-default request handling
- knock cookie issue + follow-up allow
- websocket proxy tunnel echo flow
- systemd env precondition check
