## FORMAT CODE

Run `go fmt ./...` before committing Go changes.

## TESTING IN CODEX

In the Codex sandbox, the repository root has no Go files, so do not use `go test ./...`.

Use a writable Go build cache outside the repository and test the actual packages:

```sh
env GOCACHE=/private/tmp/go-build go test ./cmd/... ./internal/...
```

On Linux, use `/tmp` instead.

Some tests bind local `httptest` or TCP ports. If sandboxing blocks local port binding, rerun the same command with the required escalation approval.
