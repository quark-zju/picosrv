package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"
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
	if got, want := entry["msg"], "TLS handshake error"; got != want {
		t.Fatalf("msg = %v, want %q", got, want)
	}
	if got, want := entry["client_ip"], "1.2.3.4"; got != want {
		t.Fatalf("client_ip = %v, want %q", got, want)
	}
	if got, want := entry["remote_addr"], "1.2.3.4:1234"; got != want {
		t.Fatalf("remote_addr = %v, want %q", got, want)
	}
	if got, want := entry["tls_error"], "missing SNI server name"; got != want {
		t.Fatalf("tls_error = %v, want %q", got, want)
	}
	if got, want := entry["ban_candidate"], true; got != want {
		t.Fatalf("ban_candidate = %v, want %v", got, want)
	}
	if got, want := entry["ban_reason"], "tls_handshake_failed"; got != want {
		t.Fatalf("ban_reason = %v, want %q", got, want)
	}
	if got, want := entry["decision_reason"], ""; got != want {
		t.Fatalf("decision_reason = %v, want %q", got, want)
	}
}

func TestSlogErrorLogParsesIPv6TLSClient(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	stdlog := slogErrorLog(logger)
	stdlog.Print("http: TLS handshake error from [2001:db8::1]:443: missing SNI server name")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	if got, want := entry["client_ip"], "2001:db8::1"; got != want {
		t.Fatalf("client_ip = %v, want %q", got, want)
	}
	if got, want := entry["remote_addr"], "[2001:db8::1]:443"; got != want {
		t.Fatalf("remote_addr = %v, want %q", got, want)
	}
}

func TestSlogErrorLogPreservesUnknownMessages(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	stdlog := slogErrorLog(logger)
	stdlog.Print("http: unrelated server error")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log entry: %v", err)
	}
	if got, want := entry["msg"], "http: unrelated server error"; got != want {
		t.Fatalf("msg = %v, want %q", got, want)
	}
	if _, ok := entry["client_ip"]; ok {
		t.Fatalf("unexpected client_ip in fallback entry: %v", entry)
	}
}

func TestTLSHandshakeBanMetadata(t *testing.T) {
	tests := []struct {
		name               string
		tlsError           string
		wantCandidate      bool
		wantDecisionReason string
		wantBanReason      string
	}{
		{
			name:               "SSLv2 probe",
			tlsError:           "tls: unsupported SSLv2 handshake received",
			wantCandidate:      true,
			wantDecisionReason: "likely_abuse",
			wantBanReason:      "tls_handshake_failed",
		},
		{
			name:          "missing SNI",
			tlsError:      "missing SNI server name",
			wantCandidate: true,
			wantBanReason: "tls_handshake_failed",
		},
		{
			name:          "unsupported TLS versions",
			tlsError:      "tls: client offered only unsupported versions: [301 302]",
			wantCandidate: true,
			wantBanReason: "tls_handshake_failed",
		},
		{
			name:          "plaintext HTTP",
			tlsError:      "client sent an HTTP request to an HTTPS server",
			wantCandidate: true,
			wantBanReason: "tls_handshake_failed",
		},
		{name: "timeout", tlsError: "read tcp 192.0.2.1:443->198.51.100.2:1234: i/o timeout"},
		{name: "EOF", tlsError: "EOF"},
		{name: "connection reset", tlsError: "read tcp: connection reset by peer"},
		{name: "unknown TLS error", tlsError: "tls: unexpected message"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate, decisionReason, banReason := tlsHandshakeBanMetadata(tt.tlsError)
			if candidate != tt.wantCandidate {
				t.Fatalf("banCandidate = %v, want %v", candidate, tt.wantCandidate)
			}
			if decisionReason != tt.wantDecisionReason {
				t.Fatalf("decisionReason = %q, want %q", decisionReason, tt.wantDecisionReason)
			}
			if banReason != tt.wantBanReason {
				t.Fatalf("banReason = %q, want %q", banReason, tt.wantBanReason)
			}
		})
	}
}

func TestValidateHMACSecretRejectsPlaceholder(t *testing.T) {
	if err := validateHMACSecret(placeholderHMACSecret); err == nil {
		t.Fatal("expected placeholder secret to be rejected")
	}
}

func TestValidateHMACSecretRejectsShortSecret(t *testing.T) {
	if err := validateHMACSecret("short"); err == nil {
		t.Fatal("expected short secret to be rejected")
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

func TestConnectionLimiterSharesCapacity(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	limited := newConnectionLimiter(1).Wrap(listener)
	firstClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	firstServer, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := limited.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	secondClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer secondClient.Close()
	if err := secondClient.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := secondClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection above the limit remained open")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("timed out waiting for connection above the limit to close")
	}

	if err := firstServer.Close(); err != nil {
		t.Fatal(err)
	}
	thirdClient, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer thirdClient.Close()

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("released capacity was not reusable")
	}
}
