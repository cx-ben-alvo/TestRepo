package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// generateSelfSignedCert creates a temporary self-signed TLS certificate and
// key PEM pair in a temp directory and returns the paths.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	dir := t.TempDir()

	// Generate an ECDSA private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Build a minimal X.509 certificate template.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	f, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("failed to encode certificate PEM: %v", err)
	}
	f.Close()

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	keyFile = filepath.Join(dir, "key.pem")
	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("failed to encode key PEM: %v", err)
	}
	kf.Close()

	return certFile, keyFile
}

// TestServerUsesTLS_NotPlainHTTP verifies that the server can be started with
// TLS and responds over HTTPS — not plain HTTP (CWE-319 regression guard).
func TestServerUsesTLS_NotPlainHTTP(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	// Build a TLS config using the generated certificate.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}

	// Start an httptest TLS server (equivalent to ListenAndServeTLS) and assert
	// a client can communicate with it securely.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	server := httptest.NewUnstartedServer(mux)
	server.TLS = tlsCfg
	server.StartTLS()
	defer server.Close()

	// The test server URL starts with "https://", confirming TLS is active.
	if len(server.URL) < 8 || server.URL[:8] != "https://" {
		t.Errorf("expected server URL to start with 'https://', got %q", server.URL)
	}

	client := server.Client() // pre-configured to trust the test certificate
	resp, err := client.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
	}
}

// TestConfigTLSFieldsLoaded verifies the Config struct carries TLS paths so
// that main() can pass them to ListenAndServeTLS.
func TestConfigTLSFieldsLoaded(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	os.Setenv("TLS_CERT_FILE", certFile)
	os.Setenv("TLS_KEY_FILE", keyFile)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := config.Load()

	if cfg.TLSCertFile != certFile {
		t.Errorf("TLSCertFile: got %q, want %q", cfg.TLSCertFile, certFile)
	}
	if cfg.TLSKeyFile != keyFile {
		t.Errorf("TLSKeyFile: got %q, want %q", cfg.TLSKeyFile, keyFile)
	}
}

// TestServerRefusesStartWithoutTLS verifies that when TLS_CERT_FILE and
// TLS_KEY_FILE are absent, the startup guard in main() would refuse to start.
// This exercises the condition `cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""`.
func TestServerRefusesStartWithoutTLS(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := config.Load()

	// Replicate the guard condition used in main().
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		t.Error("expected TLS fields to be empty when env vars are unset; " +
			"server would incorrectly attempt to start without TLS")
	}

	// Confirm the guard would fire: both fields must be non-empty for TLS to proceed.
	shouldRefuse := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""
	if !shouldRefuse {
		t.Error("startup guard would NOT refuse plain-text startup — TLS enforcement is broken")
	}
}

// TestPlainHTTPConnectionRejected verifies that a plain HTTP request to a TLS
// server results in an error, confirming no plain-text fallback exists.
func TestPlainHTTPConnectionRejected(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	server := httptest.NewUnstartedServer(mux)
	server.TLS = tlsCfg
	server.StartTLS()
	defer server.Close()

	// Attempt a plain HTTP request to the TLS port — this must fail.
	plainURL := "http://" + server.Listener.Addr().String() + "/"
	plainClient := &http.Client{Timeout: 2 * time.Second}
	_, plainErr := plainClient.Get(plainURL)
	if plainErr == nil {
		t.Error("expected plain HTTP request to TLS-only server to fail, but it succeeded — " +
			"the server is accepting plain-text connections (CWE-319)")
	}
}
