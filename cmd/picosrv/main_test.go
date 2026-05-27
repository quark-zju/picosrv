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

func TestSlogErrorLogEmitsJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	stdlog := slogErrorLog(logger)
	if stdlog == nil {
		t.Fatal("slogErrorLog returned nil")
	}
	stdlog.Output(2, "http: TLS handshake error from 1.2.3.4:1234: missing SNI server name")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	if got, want := entry["level"], "ERROR"; got != want {
		t.Fatalf("level = %v, want %q", got, want)
	}
	if _, ok := entry["msg"].(string); !ok {
		t.Fatalf("msg is missing or not a string: %v", entry["msg"])
	}
}

func TestValidateHMACSecretRejectsPlaceholder(t *testing.T) {
	if err := validateHMACSecret(placeholderHMACSecret); err == nil {
		t.Fatal("expected placeholder secret to be rejected")
	}
}

func TestValidateHMACSecretAllowsCustomSecret(t *testing.T) {
	if err := validateHMACSecret("custom-long-random-secret"); err != nil {
		t.Fatalf("expected custom secret to be allowed: %v", err)
	}
}

func TestParsePositiveInt(t *testing.T) {
	value, err := parsePositiveInt("65536")
	if err != nil {
		t.Fatal(err)
	}
	if value != 65536 {
		t.Fatalf("value = %d, want 65536", value)
	}
}

func TestParsePositiveIntRejectsZero(t *testing.T) {
	if _, err := parsePositiveInt("0"); err == nil {
		t.Fatal("expected zero to be rejected")
	}
}
