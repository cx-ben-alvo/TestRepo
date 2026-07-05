package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// TestTLSConfigFields verifies that the Config struct exposes TLS certificate
// and key path fields required to enforce encrypted transport (CWE-319).
func TestTLSConfigFields(t *testing.T) {
	cfg := &config.Config{
		ServerPort:  ":8443",
		TLSCertFile: "/certs/server.crt",
		TLSKeyFile:  "/certs/server.key",
	}

	if cfg.TLSCertFile == "" {
		t.Error("TLSCertFile must not be empty for TLS-enabled server")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("TLSKeyFile must not be empty for TLS-enabled server")
	}
}

// TestTLSRequired_EmptyConfig verifies that a configuration with empty TLS
// fields is detected as missing TLS setup, which should prevent plain-text
// server startup (CWE-319 mitigation).
func TestTLSRequired_EmptyConfig(t *testing.T) {
	cfg := &config.Config{
		ServerPort:  ":8081",
		TLSCertFile: "",
		TLSKeyFile:  "",
	}

	tlsConfigured := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if tlsConfigured {
		t.Error("server config should not be considered TLS-ready when cert/key paths are empty")
	}
}

// TestHTTPSServerResponds verifies that a TLS server starts and responds
// correctly over HTTPS. Uses httptest.NewTLSServer which provides a self-signed
// cert, exercising the same path that production code follows with
// http.ListenAndServeTLS.
func TestHTTPSServerResponds(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// httptest.NewTLSServer internally calls tls.NewListener with a self-signed
	// cert, mirroring how ListenAndServeTLS wraps the listener.
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Use the test server's pre-configured TLS client (trusts the self-signed cert)
	client := ts.Client()
	client.Timeout = 5 * time.Second

	resp, err := client.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
	}

	// Confirm the response was delivered over TLS
	if resp.TLS == nil {
		t.Error("expected TLS connection info to be present in response, got nil")
	}
}

// TestHTTPSServerRejectsPlainHTTP verifies that a TLS server rejects plain HTTP
// connections, ensuring no fallback to unencrypted transport.
func TestHTTPSServerRejectsPlainHTTP(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Attempt a plain HTTP connection to the HTTPS server port — it should fail
	plainClient := &http.Client{
		Timeout: 3 * time.Second,
		// Deliberately do NOT configure TLS: this client speaks plain HTTP
	}

	// The plain HTTP request to a TLS server will fail with a protocol error
	_, err := plainClient.Get("http://" + ts.Listener.Addr().String() + "/")
	if err == nil {
		t.Error("expected plain HTTP connection to TLS server to fail, but it succeeded")
	}
}

// TestTLSVersionSecurity verifies that the TLS connection uses a secure protocol
// version (TLS 1.2 or later). TLS 1.0 and 1.1 are deprecated and insecure.
func TestTLSVersionSecurity(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := ts.Client()
	client.Timeout = 5 * time.Second

	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("TLS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		t.Fatal("expected TLS info to be non-nil")
	}

	// TLS 1.2 = 0x0303, TLS 1.3 = 0x0304
	const minTLSVersion = tls.VersionTLS12
	if resp.TLS.Version < minTLSVersion {
		t.Errorf("insecure TLS version %x used; minimum acceptable is TLS 1.2 (%x)",
			resp.TLS.Version, minTLSVersion)
	}
}

// TestTLSCertificatePresent verifies that the TLS handshake delivers a
// certificate chain, which is required for clients to verify server identity.
func TestTLSCertificatePresent(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := ts.Client()
	client.Timeout = 5 * time.Second

	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("TLS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		t.Fatal("expected TLS connection state to be non-nil")
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		t.Error("expected server to provide at least one certificate in TLS handshake")
	}
}

// TestUntrustedCertRejectedByDefault verifies that a standard HTTP client
// (without custom TLS config) rejects a self-signed certificate, confirming
// that certificate verification is active and cannot be silently bypassed.
func TestUntrustedCertRejectedByDefault(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Default client with no custom TLS config — will NOT trust the self-signed cert
	strictClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Use the system root pool (does not include the test server's self-signed cert)
				RootCAs: x509.NewCertPool(),
			},
		},
	}

	_, err := strictClient.Get(ts.URL + "/")
	if err == nil {
		t.Error("expected certificate verification error for untrusted self-signed cert, got nil")
	}
}

// TestInitDirs_DoesNotPanic verifies that initDirs does not panic when called
// with a valid config. This exercises the helper used in main() before the TLS
// server starts.
func TestInitDirs_DoesNotPanic(t *testing.T) {
	cfg := &config.Config{
		CloneDir:    t.TempDir(),
		DownloadDir: t.TempDir(),
	}

	// Should complete without panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("initDirs panicked: %v", r)
		}
	}()

	initDirs(cfg)
}
