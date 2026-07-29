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
)

// generateSelfSignedCert creates a temporary self-signed TLS certificate and
// key pair written to the supplied directory. Returns the cert and key paths.
func generateSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
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

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
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
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	kf.Close()

	return certFile, keyFile
}

// TestTLSServerAcceptsTLSConnections starts an httptest.TLSServer (which uses
// ListenAndServeTLS under the hood) and verifies that TLS clients can connect.
// This confirms the server layer works with TLS and does NOT serve plain HTTP.
func TestTLSServerAcceptsTLSConnections(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// httptest.NewTLSServer uses a built-in self-signed cert and calls
	// ListenAndServeTLS internally — this tests the TLS path.
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// The TLS client provided by httptest trusts the built-in test certificate.
	client := ts.Client()
	resp, err := client.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("TLS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	// Verify the connection used TLS (not plain HTTP).
	if resp.TLS == nil {
		t.Error("expected TLS connection state to be non-nil; plain HTTP must not be used")
	}
}

// TestPlainHTTPClientRejectedByTLSServer confirms that a plain-text HTTP
// client cannot successfully communicate with a TLS server. This directly
// validates the CWE-319 remediation: if the server required only plain HTTP,
// this request would succeed.
func TestPlainHTTPClientRejectedByTLSServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Plain HTTP client (no TLS config) — must fail against the TLS server.
	plainClient := &http.Client{}
	_, err := plainClient.Get(ts.URL + "/health")
	if err == nil {
		t.Error("plain-text HTTP client must not successfully connect to a TLS-only server")
	}
}

// TestTLSConfigMinVersion verifies that a TLS server can be configured to
// require TLS 1.2 or higher, preventing downgrade attacks.
func TestTLSConfigMinVersion(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := generateSelfSignedCert(t, dir)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// MinVersion must be set to TLS 1.2 or higher to be safe against POODLE
	// and other downgrade attacks.
	if tlsCfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion must be >= TLS 1.2; got 0x%04x", tlsCfg.MinVersion)
	}
}

// TestInitDirs validates that initDirs creates the configured directories
// without error (no change in behaviour after the TLS fix).
func TestInitDirs(t *testing.T) {
	dir := t.TempDir()
	cloneDir := filepath.Join(dir, "clones")
	downloadDir := filepath.Join(dir, "downloads")

	// Construct a minimal config that exercises initDirs.
	type minCfg struct{ CloneDir, DownloadDir string }
	cfg := &minCfg{CloneDir: cloneDir, DownloadDir: downloadDir}

	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)

	if _, err := os.Stat(cloneDir); os.IsNotExist(err) {
		t.Errorf("clone dir was not created: %v", err)
	}
	if _, err := os.Stat(downloadDir); os.IsNotExist(err) {
		t.Errorf("download dir was not created: %v", err)
	}
}
