package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsumeBasicAuth(t *testing.T) {
	tests := []struct {
		name             string
		user             string
		password         string
		expectedUser     string
		expectedPassword string
		wantValid        bool
		wantHeader       bool
	}{
		{
			name:             "valid",
			user:             "alice",
			password:         "correct horse battery staple",
			expectedUser:     "alice",
			expectedPassword: "correct horse battery staple",
			wantValid:        true,
		},
		{
			name:             "wrong user",
			user:             "mallory",
			password:         "correct horse battery staple",
			expectedUser:     "alice",
			expectedPassword: "correct horse battery staple",
			wantHeader:       true,
		},
		{
			name:             "wrong password",
			user:             "alice",
			password:         "wrong",
			expectedUser:     "alice",
			expectedPassword: "correct horse battery staple",
			wantHeader:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.local/private", nil)
			req.SetBasicAuth(tt.user, tt.password)
			auth := &requestAuth{request: req}

			if got := auth.ConsumeBasicAuth(tt.expectedUser, tt.expectedPassword); got != tt.wantValid {
				t.Fatalf("ConsumeBasicAuth() = %v, want %v", got, tt.wantValid)
			}
			if got := req.Header.Get("Authorization") != ""; got != tt.wantHeader {
				t.Fatalf("Authorization header present = %v, want %v", got, tt.wantHeader)
			}
		})
	}
}
