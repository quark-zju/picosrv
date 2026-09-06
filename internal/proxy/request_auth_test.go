package proxy

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"picosrv/internal/config"
)

func TestConsumeBasicAuth(t *testing.T) {
	tests := []struct {
		name             string
		user             string
		password         string
		expectedUser     string
		expectedPassword config.Password
		setBasicAuth     bool
		wantValid        bool
		wantPresent      bool
		wantHeader       bool
	}{
		{
			name:             "valid",
			user:             "alice",
			password:         "correct horse battery staple",
			expectedUser:     "alice",
			expectedPassword: config.PlainPassword("correct horse battery staple"),
			setBasicAuth:     true,
			wantValid:        true,
			wantPresent:      true,
		},
		{
			name:             "valid with sha256 password",
			user:             "alice",
			password:         "correct horse battery staple",
			expectedUser:     "alice",
			expectedPassword: config.Sha256Encoded(fmt.Sprintf("%x", sha256.Sum256([]byte("correct horse battery staple")))),
			setBasicAuth:     true,
			wantValid:        true,
			wantPresent:      true,
		},
		{
			name:             "wrong user",
			user:             "mallory",
			password:         "correct horse battery staple",
			expectedUser:     "alice",
			expectedPassword: config.PlainPassword("correct horse battery staple"),
			setBasicAuth:     true,
			wantPresent:      true,
			wantHeader:       true,
		},
		{
			name:             "wrong password",
			user:             "alice",
			password:         "wrong",
			expectedUser:     "alice",
			expectedPassword: config.PlainPassword("correct horse battery staple"),
			setBasicAuth:     true,
			wantPresent:      true,
			wantHeader:       true,
		},
		{
			name:             "no credentials",
			expectedUser:     "alice",
			expectedPassword: config.PlainPassword("correct horse battery staple"),
			wantPresent:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.local/private", nil)
			if tt.setBasicAuth {
				req.SetBasicAuth(tt.user, tt.password)
			}
			auth := &requestAuth{request: req}

			if got := auth.ConsumeBasicAuth(tt.expectedUser, tt.expectedPassword); got != tt.wantValid {
				t.Fatalf("ConsumeBasicAuth() = %v, want %v", got, tt.wantValid)
			}
			if got := auth.basicAuthCredentialsPresent; got != tt.wantPresent {
				t.Fatalf("basicAuthCredentialsPresent = %v, want %v", got, tt.wantPresent)
			}
			if got := req.Header.Get("Authorization") != ""; got != tt.wantHeader {
				t.Fatalf("Authorization header present = %v, want %v", got, tt.wantHeader)
			}
		})
	}
}
