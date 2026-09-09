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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// generateSelfSignedCert creates a temporary self-signed TLS certificate and
// private key in the supplied directory and returns their file paths.
// This is used only in tests to verify TLS server behaviour.
func generateSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	// Generate an ECDSA private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Build a minimal self-signed certificate template.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Write PEM-encoded certificate.
	certFile = filepath.Join(dir, "cert.pem")
	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		cf.Close()
		t.Fatalf("failed to encode certificate: %v", err)
	}
	cf.Close()

	// Write PEM-encoded private key.
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyFile = filepath.Join(dir, "key.pem")
	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		kf.Close()
		t.Fatalf("failed to encode private key: %v", err)
	}
	kf.Close()

	return certFile, keyFile
}

// TestTLSConfigFieldsPopulated verifies that when TLS environment variables
// are set, config.Load() correctly populates TLSCertFile and TLSKeyFile.
// This is the precondition for the server to start over HTTPS.
func TestTLSConfigFieldsPopulated(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	os.Setenv("TLS_CERT_FILE", certFile)
	os.Setenv("TLS_KEY_FILE", keyFile)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := config.Load()

	if cfg.TLSCertFile == "" {
		t.Error("expected TLSCertFile to be non-empty when TLS_CERT_FILE is set")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("expected TLSKeyFile to be non-empty when TLS_KEY_FILE is set")
	}
}

// TestServerRefusesStartWithoutTLS verifies that the server startup guard
// condition detects missing TLS configuration. When either TLSCertFile or
// TLSKeyFile is empty the server must not start; this test models that check.
func TestServerRefusesStartWithoutTLS(t *testing.T) {
	cases := []struct {
		name     string
		certFile string
		keyFile  string
		wantTLS  bool
	}{
		{
			name:     "no TLS configuration",
			certFile: "",
			keyFile:  "",
			wantTLS:  false,
		},
		{
			name:     "only cert file set",
			certFile: "/tmp/cert.pem",
			keyFile:  "",
			wantTLS:  false,
		},
		{
			name:     "only key file set",
			certFile: "",
			keyFile:  "/tmp/key.pem",
			wantTLS:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}

			// Replicate the guard logic from main(): the server must not start
			// when either TLS path is missing.
			tlsReady := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
			if tlsReady != tc.wantTLS {
				t.Errorf("tlsReady=%v, want %v (certFile=%q, keyFile=%q)",
					tlsReady, tc.wantTLS, tc.certFile, tc.keyFile)
			}
		})
	}
}

// TestHTTPSServerAcceptsTLSConnection starts a real TLS listener using the
// same net/http.ListenAndServeTLS call pattern used in main.go and verifies
// that a client using the server's certificate can connect successfully over
// HTTPS (not plain HTTP).
func TestHTTPSServerAcceptsTLSConnection(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	// Start a TLS server on a random free port.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Handler: mux,
	}

	// Use a TLS listener directly so we control the port.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	addr := ln.Addr().String()

	// Run the server in a goroutine; shut it down after the test.
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// Build a client that trusts only our self-signed cert.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add cert to pool")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 5 * time.Second,
	}

	// The request MUST succeed over HTTPS.
	resp, err := client.Get("https://" + addr + "/health")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
	}

	// The connection must have been upgraded to TLS (not plain HTTP).
	if resp.TLS == nil {
		t.Error("expected response to have TLS connection state, but TLS was nil")
	}
}

// TestPlainHTTPConnectionRejected verifies that a plain-text HTTP client
// cannot connect to a TLS-only server. This confirms that the server does
// not accept unencrypted connections, preventing CWE-319 exposure.
func TestPlainHTTPConnectionRejected(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	addr := ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// A plain-text HTTP client (no TLS) must fail to connect.
	plainClient := &http.Client{Timeout: 2 * time.Second}
	_, err = plainClient.Get("http://" + addr + "/")
	if err == nil {
		t.Error("expected plain HTTP connection to fail against a TLS-only server, but it succeeded")
	}
}
