package main

import (
	"testing"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// TestRequireTLS_RejectsPlainTextFallback verifies that the server startup gate
// rejects a configuration that would cause plain-text HTTP to be used (CWE-319).
// This is the core regression test for the Plain_Text_Transport_Layer_in_Server
// finding: net/http.ListenAndServe must never be reachable at startup.
func TestRequireTLS_RejectsPlainTextFallback(t *testing.T) {
	cases := []struct {
		name        string
		certFile    string
		keyFile     string
		wantErr     bool
		description string
	}{
		{
			name:        "no TLS config – server must refuse to start",
			certFile:    "",
			keyFile:     "",
			wantErr:     true,
			description: "plain-text ListenAndServe would be used; server must not start",
		},
		{
			name:        "only cert set – server must refuse to start",
			certFile:    "/etc/ssl/certs/server.crt",
			keyFile:     "",
			wantErr:     true,
			description: "partial TLS config must not allow plain-text fallback",
		},
		{
			name:        "only key set – server must refuse to start",
			certFile:    "",
			keyFile:     "/etc/ssl/private/server.key",
			wantErr:     true,
			description: "partial TLS config must not allow plain-text fallback",
		},
		{
			name:        "both cert and key set – TLS path is taken",
			certFile:    "/etc/ssl/certs/server.crt",
			keyFile:     "/etc/ssl/private/server.key",
			wantErr:     false,
			description: "full TLS config must allow the server to proceed to ListenAndServeTLS",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				ServerPort:  ":8443",
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}

			err := requireTLS(cfg)

			if tc.wantErr && err == nil {
				t.Errorf("requireTLS() = nil, want error (%s)", tc.description)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("requireTLS() = %v, want nil (%s)", err, tc.description)
			}
		})
	}
}

// TestRequireTLS_ErrorMessageIsInformative verifies that the error message from
// requireTLS is actionable — it must tell operators which environment variables
// to set to enable TLS and satisfy the security requirement.
func TestRequireTLS_ErrorMessageIsInformative(t *testing.T) {
	cfg := &config.Config{
		ServerPort:  ":8080",
		TLSCertFile: "",
		TLSKeyFile:  "",
	}

	err := requireTLS(cfg)
	if err == nil {
		t.Fatal("requireTLS() returned nil for unconfigured TLS; expected an error")
	}

	msg := err.Error()
	// The error must mention both environment variables so the operator knows how to fix it.
	for _, expected := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE"} {
		found := false
		for i := 0; i <= len(msg)-len(expected); i++ {
			if msg[i:i+len(expected)] == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("requireTLS() error %q does not mention %q", msg, expected)
		}
	}
}

// TestRequireTLS_PlainTextSinkUnreachable documents the security invariant:
// when requireTLS returns nil (no error), TLSEnabled() must be true, meaning
// the server will call ListenAndServeTLS (not the plain-text ListenAndServe).
// This provides traceability from the CWE-319 finding to the code gate.
func TestRequireTLS_PlainTextSinkUnreachable(t *testing.T) {
	cfg := &config.Config{
		ServerPort:  ":8443",
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}

	err := requireTLS(cfg)
	if err != nil {
		t.Fatalf("requireTLS() returned unexpected error: %v", err)
	}

	// After requireTLS succeeds, TLSEnabled must be true.
	// This guarantees ListenAndServeTLS is used, never ListenAndServe.
	if !cfg.TLSEnabled() {
		t.Error("after requireTLS() passes, cfg.TLSEnabled() must be true " +
			"(plain-text ListenAndServe must be unreachable)")
	}
}
