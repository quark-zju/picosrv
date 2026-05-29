## ALWAYS COMMIT

Always create a `git commit` after code changes, even if the user did not ask.

Break work down into small atomic commits. Use one commit per logical step.

Commit with:

```sh
git commit -m 'TITLE' -m 'User request: TEXT' -m 'Decision: TEXT'
```

Avoid backticks in commit messages because they trigger shell command substitution.

## PAUSE IF STUCK

If you make little to no progress after 15 consecutive attempts, halt execution and ask the user for guidance.

## SAVE CONTEXT

Avoid large outputs. Prefer `git diff --stat` to `git diff`. Prefer bounded command output when possible.

## FORMAT CODE

Run `go fmt ./...` before committing Go changes.

## TESTING IN CODEX

In the Codex sandbox, the repository root has no Go files, so do not use `go test ./...`.

Use a writable Go build cache outside the repository and test the actual packages:

```sh
env GOCACHE=/private/tmp/go-build go test ./cmd/... ./internal/...
```

On Linux, use `/tmp` instead:

```sh
env GOCACHE=/tmp/go-build go test ./cmd/... ./internal/...
```

Some tests bind local `httptest` or TCP ports. If sandboxing blocks local port binding, rerun the same command with the required escalation approval.
