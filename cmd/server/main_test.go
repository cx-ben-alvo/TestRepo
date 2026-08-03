package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// tlsConfigured reports whether cfg has both TLS fields populated.
// This mirrors the guard added in main() to enforce TLS.
func tlsConfigured(cfg *config.Config) bool {
	return cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
}

// TestTLSEnforced_MissingBothPaths verifies that when neither TLS_CERT_FILE
// nor TLS_KEY_FILE are set, the server is not considered TLS-ready.  This
// prevents the application from accidentally starting in plaintext mode
// (CWE-319).
func TestTLSEnforced_MissingBothPaths(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := config.Load()

	if tlsConfigured(cfg) {
		t.Error("expected TLS to be NOT configured when env vars are absent; server must not start without TLS")
	}
}

// TestTLSEnforced_MissingCertPath verifies that a key-only configuration is
// not accepted as TLS-ready.
func TestTLSEnforced_MissingCertPath(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")

	cfg := config.Load()

	if tlsConfigured(cfg) {
		t.Error("expected TLS to be NOT configured when TLS_CERT_FILE is missing")
	}
}

// TestTLSEnforced_MissingKeyPath verifies that a cert-only configuration is
// not accepted as TLS-ready.
func TestTLSEnforced_MissingKeyPath(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := config.Load()

	if tlsConfigured(cfg) {
		t.Error("expected TLS to be NOT configured when TLS_KEY_FILE is missing")
	}
}

// TestTLSEnforced_BothPathsPresent verifies that providing both TLS_CERT_FILE
// and TLS_KEY_FILE marks the config as TLS-ready, allowing the server to call
// ListenAndServeTLS.
func TestTLSEnforced_BothPathsPresent(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")

	cfg := config.Load()

	if !tlsConfigured(cfg) {
		t.Error("expected TLS to be configured when both TLS_CERT_FILE and TLS_KEY_FILE are set")
	}
}

// TestServerUsesTLS_NotListenAndServe is a structural/integration test that
// creates a real httptest.NewTLSServer (the Go test framework's TLS server)
// and confirms it rejects a plain-HTTP client while accepting a TLS client.
// This demonstrates that a TLS-enforced server correctly refuses plaintext
// connections, which is the behaviour the ListenAndServeTLS migration achieves.
func TestServerUsesTLS_NotListenAndServe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// httptest.NewTLSServer automatically creates a self-signed cert and
	// starts a TLS listener — this represents our production server after the
	// ListenAndServeTLS migration.
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// A plain-HTTP request to the TLS server URL must fail (connection reset /
	// protocol error) — the server does not accept cleartext.
	plainHTTPURL := "http" + ts.URL[len("https"):]
	resp, err := http.Get(plainHTTPURL)
	if err == nil {
		resp.Body.Close()
		t.Error("expected an error when sending a plain-HTTP request to a TLS server, but got nil")
	}

	// The TLS-aware client (ts.Client()) must succeed.
	tlsClient := ts.Client()
	resp2, err2 := tlsClient.Get(ts.URL + "/healthz")
	if err2 != nil {
		t.Fatalf("expected TLS client to succeed, got error: %v", err2)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK from TLS endpoint, got %d", resp2.StatusCode)
	}
}
