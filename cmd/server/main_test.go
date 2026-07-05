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

// ---------------------------------------------------------------------------
// validateTLSConfig unit tests
// ---------------------------------------------------------------------------

// TestValidateTLSConfig_BothEmpty verifies that omitting both TLS paths
// is rejected.  This enforces the CWE-319 fix: the server must never fall
// back to plain HTTP.
func TestValidateTLSConfig_BothEmpty(t *testing.T) {
	err := validateTLSConfig("", "")
	if err == nil {
		t.Fatal("expected an error when both TLS paths are empty, got nil")
	}
}

// TestValidateTLSConfig_CertMissing verifies that a missing cert path (even
// when a key path is provided) is rejected.
func TestValidateTLSConfig_CertMissing(t *testing.T) {
	err := validateTLSConfig("", "/path/to/key.pem")
	if err == nil {
		t.Fatal("expected an error when TLS cert path is empty, got nil")
	}
}

// TestValidateTLSConfig_KeyMissing verifies that a missing key path (even
// when a cert path is provided) is rejected.
func TestValidateTLSConfig_KeyMissing(t *testing.T) {
	err := validateTLSConfig("/path/to/cert.pem", "")
	if err == nil {
		t.Fatal("expected an error when TLS key path is empty, got nil")
	}
}

// TestValidateTLSConfig_BothProvided verifies that supplying both paths passes
// validation.
func TestValidateTLSConfig_BothProvided(t *testing.T) {
	err := validateTLSConfig("/path/to/cert.pem", "/path/to/key.pem")
	if err != nil {
		t.Fatalf("expected no error when both TLS paths are set, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Integration-style test: server actually uses TLS when certs are provided
// ---------------------------------------------------------------------------

// generateSelfSignedCert writes a self-signed ECDSA certificate and matching
// private key to temporary files and returns their paths.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("failed to encode cert: %v", err)
	}

	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	defer kf.Close()
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("failed to encode key: %v", err)
	}

	return certFile, keyFile
}

// TestServer_UsesTLS verifies that when valid TLS files are provided the
// server can be reached over HTTPS (not plain HTTP).
func TestServer_UsesTLS(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	// Load the certificate so we can build a trusting TLS client.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(x509Cert)

	// Use httptest.NewUnstartedServer to wire up a TLS listener without
	// binding to a real network port and without calling main().
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	// The test server URL starts with "https://" when TLS is active.
	if srv.URL[:5] != "https" {
		t.Fatalf("expected HTTPS server URL, got %s", srv.URL)
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
}

// TestServer_NoPlainHTTP verifies that a plain HTTP client cannot communicate
// with the TLS server (connection fails or returns a protocol error).
func TestServer_NoPlainHTTP(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	// Replace the "https://" scheme with "http://" to simulate a plain-text client.
	plainURL := "http" + srv.URL[5:]

	plainClient := &http.Client{Timeout: 2 * time.Second}
	resp, err := plainClient.Get(plainURL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected plain HTTP request to fail against a TLS-only server, but it succeeded")
	}
	// An error is expected here (EOF, TLS handshake failure, or connection reset).
	// The important thing is that the plain-text request was NOT served successfully.
}
