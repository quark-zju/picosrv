# Code Review Findings

## Critical

### 1. UA "healthcheck" bypasses all access control

**File:** `internal/config/default_config.go:28-30`

```go
if strings.HasPrefix(strings.ToLower(ctx.UA), "healthcheck") {
    return Decision{Kind: DecisionAllowProxy, Upstream: upstream, AllowReason: "ua_whitelist"}
}
```

Anyone can set `User-Agent: healthcheck` to bypass cookie-based access control entirely. This is trivial to exploit.

**Suggested fix:** Either remove this bypass entirely, or require it to be combined with another factor (e.g., source IP or a separate secret header).

---

### 2. `http.Error` called on a hijacked connection

**File:** `internal/proxy/server.go:145-150`

```go
if err := s.proxyWebSocket(w, r, decision.Upstream); err != nil {
    status = http.StatusBadGateway
    http.Error(w, "bad gateway", status)
    ...
}
```

When `proxyWebSocket` successfully hijacks the connection (`hj.Hijack()`), subsequent failures (e.g., `clone.Write` or `clientRW.Flush`) still return an error. Back in `serveHTTP`, `http.Error(w, ...)` is then called on the already-hijacked `ResponseWriter`, which may panic or write garbage to the raw TCP connection.

**Suggested fix:** After a successful hijack, the function should not return to the `http.Error` path. All error handling after hijack should be self-contained within `proxyWebSocket`.

---

## High

### 3. Per-request map allocation in `defaultHostUpstreams()`

**File:** `internal/config/default_config.go:40-43`

```go
func defaultHostUpstreams() map[string]string {
    return map[string]string{
        "example.local": "http://127.0.0.1:8081",
    }
}
```

Called on every single HTTP request (`Evaluate` -> `defaultHostUpstreams()`). Allocates a new heap-escaped map each time.

**Suggested fix:** Use a package-level `var`:

```go
var defaultUpstreams = map[string]string{
    "example.local": "http://127.0.0.1:8081",
}
```

---

### 4. WebSocket `io.Copy` goroutines not synchronized

**File:** `internal/proxy/server.go:252-260`

```go
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
return nil
```

The parent reads only one error from the channel, closes both connections, and returns. The other goroutine may still be running. While `Close()` eventually unblocks `io.Copy`, there is no `sync.WaitGroup` to guarantee the goroutines have exited before the function returns.

**Suggested fix:** Use `sync.WaitGroup` and read both errors (or close the channel and range over it).

---

## Medium

### 5. Inefficient hash computation in `loadCertRecord`

**File:** `internal/proxy/server.go:483-487`

```go
h := sha256.New()
_, _ = h.Write(certPEM)
_, _ = h.Write(keyPEM)
sum := h.Sum(nil)
hash, _ := strconv.ParseUint(fmt.Sprintf("%x", sum[:8]), 16, 64)
```

Computes SHA256, formats first 8 bytes as a hex string via `fmt.Sprintf`, then parses that hex string back to `uint64`. This round-trip involves memory allocation and string parsing.

**Suggested fix:**

```go
hash := binary.BigEndian.Uint64(sum[:8])
```

Also, the error from `strconv.ParseUint` is silently ignored with `_`.

---

### 6. `exitErr` uses `os.Exit` — deferred cleanup skipped

**File:** `cmd/picosrv/main.go:118-120`

```go
func exitErr(err error) {
    _, _ = os.Stderr.WriteString(err.Error() + "\n")
    os.Exit(1)
}
```

`os.Exit` terminates the process immediately without running any deferred functions. This means `cancel()` (line 58) and `shutdownCancel()` (line 98) are never called on error exit, though the process is terminating anyway so the impact is minimal. Also bypasses the structured logger.

---

### 7. Transport idle connections not closed on shutdown

**File:** `cmd/picosrv/main.go:97-101`

```go
shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
defer shutdownCancel()
for _, s := range httpServers {
    _ = s.Shutdown(shutdownCtx)
}
```

After shutting down the HTTP servers, `s.transport.CloseIdleConnections()` is never called. Upstream connections in the idle pool are left open until the OS cleans them up on process exit.

**Suggested fix:** Add `srv.transport.CloseIdleConnections()` after the shutdown loop.

---

## Low

### 8. `Validate` signature couples cookie and error

**File:** `internal/proxy/server.go:346`

```go
func (c *cookieSigner) Validate(cookie *http.Cookie, err error) bool {
```

The function takes both a `*http.Cookie` and an `error` (from `r.Cookie()`). This is unconventional — the caller should check the error first and only pass a valid cookie.

---

### 9. `LoadOrStore` return value ignored, wasting allocations

**File:** `internal/proxy/server.go:204`

```go
actual, _ := s.proxyByHost.LoadOrStore(target, proxy)
return actual.(*httputil.ReverseProxy), nil
```

When two concurrent requests both miss the cache for the same upstream, both parse the URL and construct a `ReverseProxy`, but only one is stored. The discarded proxy is wasted allocation.

---

### 10. No path sanitization in `loadCertRecord`

**File:** `internal/proxy/server.go:469`

```go
fullchain := certDir + "/" + domain + "/fullchain.pem"
```

The `domain` value comes from SNI (`hello.ServerName`), which is attacker-controlled. While `normalizeTopLevelDomain`'s split-by-dot logic coincidentally breaks up `..` sequences (making path traversal impractical), adding `filepath.Clean` and validating the result is still under `certDir` would be more defensive.

**Suggested fix:**

```go
fullchain := filepath.Join(certDir, domain, "fullchain.pem")
if !strings.HasPrefix(filepath.Clean(fullchain), filepath.Clean(certDir)) {
    return certRecord{}, errors.New("path traversal detected")
}
```
