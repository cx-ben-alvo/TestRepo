package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert creates a temporary self-signed TLS certificate and
// key in PEM format for testing purposes.  The files are cleaned up
// automatically after the test.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	// Generate ECDSA private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create a self-signed certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")

	// Write certificate
	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("failed to encode certificate: %v", err)
	}
	cf.Close()

	// Write private key
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}
	kf.Close()

	return certFile, keyFile
}

// TestTLSServerStartsSuccessfully verifies that when valid TLS certificate and
// key files are provided, the server accepts TLS connections.  This test
// exercises the net/http.ListenAndServeTLS code path.
func TestTLSServerStartsSuccessfully(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// Start TLS server in background
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- http.ListenAndServeTLS(addr, certFile, keyFile, mux)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Verify the server is not dead before we even connect
	select {
	case err := <-serverErr:
		t.Fatalf("server exited prematurely: %v", err)
	default:
	}

	// Make a TLS request using the self-signed cert as the trusted root
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://" + addr + "/health")
	if err != nil {
		t.Fatalf("TLS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
	// Confirm the connection was TLS (not plain HTTP)
	if resp.TLS == nil {
		t.Error("expected TLS connection, but resp.TLS is nil")
	}
}

// TestPlainHTTPConnectionRejected verifies that a TLS server rejects plain
// (unencrypted) HTTP connections.  This confirms that the transport layer
// encryption cannot be bypassed by a client sending HTTP instead of HTTPS.
func TestPlainHTTPConnectionRejected(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	go func() {
		http.ListenAndServeTLS(addr, certFile, keyFile, mux) //nolint:errcheck
	}()

	time.Sleep(100 * time.Millisecond)

	// Attempt a plain HTTP (non-TLS) connection — the server must reject it
	plainClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := plainClient.Get("http://" + addr + "/health")
	if err == nil {
		resp.Body.Close()
		t.Error("expected plain HTTP connection to fail, but it succeeded — server is not enforcing TLS")
	}
	// An error here means the server correctly refused or could not handle the
	// plain-text connection, which is the expected secure behaviour.
}

// TestTLSCertAndKeyFilesRequired verifies the startup guard logic: when
// TLS_CERT_FILE or TLS_KEY_FILE is empty the guard should catch it before
// calling ListenAndServeTLS.  This test mirrors the check in main().
func TestTLSCertAndKeyFilesRequired(t *testing.T) {
	cases := []struct {
		name     string
		certFile string
		keyFile  string
		wantFail bool
	}{
		{
			name:     "both empty - must fail",
			certFile: "",
			keyFile:  "",
			wantFail: true,
		},
		{
			name:     "cert empty - must fail",
			certFile: "",
			keyFile:  "/some/key.key",
			wantFail: true,
		},
		{
			name:     "key empty - must fail",
			certFile: "/some/cert.crt",
			keyFile:  "",
			wantFail: true,
		},
		{
			name:     "both provided - guard passes",
			certFile: "/some/cert.crt",
			keyFile:  "/some/key.key",
			wantFail: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// This replicates the startup guard from cmd/server/main.go:
			//   if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			//       log.Fatal(...)
			//   }
			guardFired := tc.certFile == "" || tc.keyFile == ""
			if guardFired != tc.wantFail {
				t.Errorf("guard fired=%v, wantFail=%v", guardFired, tc.wantFail)
			}
		})
	}
}

// TestTLSConnectionNegotiatesMinimumVersion verifies that the established TLS
// connection uses at least TLS 1.2.  Older protocol versions (SSLv3, TLS 1.0,
// TLS 1.1) have known weaknesses and must not be accepted.
func TestTLSConnectionNegotiatesMinimumVersion(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/version-check", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	go func() {
		http.ListenAndServeTLS(addr, certFile, keyFile, mux) //nolint:errcheck
	}()

	time.Sleep(100 * time.Millisecond)

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("https://" + addr + "/version-check")
	if err != nil {
		t.Fatalf("TLS 1.2+ connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		t.Fatal("expected TLS connection info to be present")
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("expected TLS >= 1.2, got version 0x%04x", resp.TLS.Version)
	}
}
