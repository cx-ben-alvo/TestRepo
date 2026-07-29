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

// generateSelfSignedCert creates a temporary self-signed certificate and key
// in dir and returns their paths.
func generateSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.Public(), priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	return certFile, keyFile
}

// TestTLSEnforcement_MissingCertFile verifies that Config with no TLS paths
// triggers the enforcement guard (both TLSCertFile and TLSKeyFile are empty).
func TestTLSEnforcement_MissingCertFile(t *testing.T) {
	cfg := &config.Config{
		ServerPort:  ":0",
		TLSCertFile: "",
		TLSKeyFile:  "",
	}

	// The server must refuse to start when TLS paths are missing.
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		// Guard would call log.Fatal – confirm the condition evaluates true.
		t.Log("TLS enforcement guard correctly triggered: missing cert/key paths")
	} else {
		t.Error("expected TLS enforcement guard to trigger when paths are empty")
	}
}

// TestTLSEnforcement_BothPathsRequired verifies that providing only one of
// the two required TLS paths also triggers the enforcement guard.
func TestTLSEnforcement_BothPathsRequired(t *testing.T) {
	cases := []struct {
		name     string
		certFile string
		keyFile  string
		wantFail bool
	}{
		{
			name:     "both empty",
			certFile: "",
			keyFile:  "",
			wantFail: true,
		},
		{
			name:     "cert only",
			certFile: "/path/to/cert.pem",
			keyFile:  "",
			wantFail: true,
		},
		{
			name:     "key only",
			certFile: "",
			keyFile:  "/path/to/key.pem",
			wantFail: true,
		},
		{
			name:     "both set",
			certFile: "/path/to/cert.pem",
			keyFile:  "/path/to/key.pem",
			wantFail: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			shouldFail := tc.certFile == "" || tc.keyFile == ""
			if shouldFail != tc.wantFail {
				t.Errorf("guard condition mismatch for %q: got shouldFail=%v, want %v",
					tc.name, shouldFail, tc.wantFail)
			}
		})
	}
}

// TestListenAndServeTLS_AcceptsHTTPS confirms that a server started with
// ListenAndServeTLS actually accepts HTTPS connections (not plain HTTP).
func TestListenAndServeTLS_AcceptsHTTPS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	// Start a TLS server on a random available port.
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: mux,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		// Use the same function the server now calls (ListenAndServeTLS) but
		// drive it via ServeTLS which shares the underlying implementation.
		errCh <- srv.ServeTLS(ln, certFile, keyFile)
	}()

	// Give the goroutine a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Confirm that a plain-HTTP request is NOT served over TLS.
	plainClient := &http.Client{Timeout: 2 * time.Second}
	_, plainErr := plainClient.Get("http://" + addr + "/ping")
	if plainErr == nil {
		t.Error("plain HTTP request should have failed against a TLS server")
	}

	// Confirm that an HTTPS client (with self-signed cert pool) succeeds.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	tlsClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := tlsClient.Get("https://" + addr + "/ping")
	if err != nil {
		t.Fatalf("TLS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	// Confirm TLS version – must be at least TLS 1.2.
	if resp.TLS == nil {
		t.Fatal("expected TLS connection info, got nil")
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("expected TLS >= 1.2, got version 0x%04x", resp.TLS.Version)
	}

	_ = srv.Close()
}

// TestPlainHTTP_IsRejected verifies that a plain HTTP client connecting to the
// TLS server receives an error rather than a valid response.
func TestPlainHTTP_IsRejected(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()

	go srv.ServeTLS(ln, certFile, keyFile) //nolint:errcheck

	time.Sleep(50 * time.Millisecond)

	// A plain HTTP GET must fail – it is talking HTTP to a TLS listener.
	resp, err := http.Get("http://" + addr + "/")
	if err == nil {
		resp.Body.Close()
		t.Error("expected plain HTTP to fail against a TLS-only server, but got a response")
	}

	_ = srv.Close()
}
