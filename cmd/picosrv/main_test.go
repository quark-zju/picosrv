package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
)

func TestLogErrEmitsJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	logErr(logger, errors.New("boom"))

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	if got, want := entry["msg"], "fatal error"; got != want {
		t.Fatalf("msg = %v, want %q", got, want)
	}
	if got, want := entry["level"], "ERROR"; got != want {
		t.Fatalf("level = %v, want %q", got, want)
	}
	if got, want := entry["error"], "boom"; got != want {
		t.Fatalf("error = %v, want %q", got, want)
	}
}
