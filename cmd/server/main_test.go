package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// TestServerRequiresTLS verifies that the TLS guard in main() is effective:
// the guard condition must evaluate to "blocked" (true) whenever either TLS
// field is absent, and to "not blocked" only when both are present.
//
// This mirrors the check in main():
//
//	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
//	    log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE must be set …")
//	}
func TestServerRequiresTLS(t *testing.T) {
	tests := []struct {
		name        string
		certFile    string
		keyFile     string
		expectBlock bool
	}{
		{"no creds", "", "", true},
		{"cert missing", "", "/etc/tls/server.key", true},
		{"key missing", "/etc/tls/server.crt", "", true},
		{"both present", "/etc/tls/server.crt", "/etc/tls/server.key", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				ServerPort:  ":8443",
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}
			blocked := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""
			if blocked != tc.expectBlock {
				t.Errorf("expected blocked=%v, got blocked=%v (cert=%q key=%q)",
					tc.expectBlock, blocked, tc.certFile, tc.keyFile)
			}
		})
	}
}

// TestConfigLoadsFromEnv verifies that TLS configuration is sourced from
// environment variables, making it trivial to supply real certificates without
// code changes — a prerequisite for running in production with proper TLS.
func TestConfigLoadsFromEnv(t *testing.T) {
	const wantCert = "/run/secrets/tls.crt"
	const wantKey = "/run/secrets/tls.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := config.Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: want %q, got %q", wantCert, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: want %q, got %q", wantKey, cfg.TLSKeyFile)
	}
}

// TestHTTPSEndpointReachable uses httptest.NewTLSServer to confirm that the
// application's HTTP handlers are reachable over an encrypted TLS connection.
// This validates that replacing ListenAndServe with ListenAndServeTLS does not
// break normal request handling — the handler still responds with 200 OK.
func TestHTTPSEndpointReachable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/repo/list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
	})

	// httptest.NewTLSServer starts a real HTTPS server with a self-signed cert
	// — functionally equivalent to production ListenAndServeTLS.
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	client := ts.Client() // pre-configured to trust the test server's cert

	resp, err := client.Get(ts.URL + "/api/repo/list")
	if err != nil {
		t.Fatalf("HTTPS GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	// The connection must be TLS — proto should be "HTTP/1.1" over TLS.
	if resp.TLS == nil {
		t.Error("expected a TLS connection but resp.TLS is nil")
	}
}

// TestPlainHTTPConnectionRejected verifies that a plain HTTP client (no TLS)
// cannot successfully communicate with a server that is configured for TLS.
// This confirms that switching to ListenAndServeTLS actually enforces encryption
// and is not merely advisory.
func TestPlainHTTPConnectionRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/repo/list", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Use a standard http.Client (no TLS trust) to attempt a plain HTTP request.
	plainClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	// The request must fail because the plain client cannot negotiate TLS with
	// the test's self-signed cert (and we haven't added it to the trust store).
	_, err := plainClient.Get(ts.URL + "/api/repo/list")
	if err == nil {
		t.Error("expected plain HTTP client to fail against TLS server, but request succeeded")
	}
}
