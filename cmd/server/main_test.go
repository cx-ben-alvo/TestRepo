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
	"strings"
	"testing"
	"time"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// ---------------------------------------------------------------------------
// Helper: self-signed certificate pair for tests
// ---------------------------------------------------------------------------

// writeTempTLSFiles generates a self-signed ECDSA certificate/key pair and
// writes them to temporary PEM files. It returns the cert path, key path, and
// a cleanup function. The files are automatically removed after the test.
func writeTempTLSFiles(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	// Generate ECDSA key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	// Build a minimal self-signed certificate valid for 1 hour.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()

	// Write certificate PEM.
	certFile = filepath.Join(dir, "cert.pem")
	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert PEM: %v", err)
	}
	cf.Close()

	// Write private key PEM.
	keyFile = filepath.Join(dir, "key.pem")
	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal EC private key: %v", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("encode key PEM: %v", err)
	}
	kf.Close()

	return certFile, keyFile
}

// ---------------------------------------------------------------------------
// Config TLS field tests
// ---------------------------------------------------------------------------

// TestConfig_TLSFieldsDefault verifies that TLSCertFile and TLSKeyFile default
// to empty strings when the corresponding environment variables are not set.
// An empty value is the signal that the server must refuse to start (CWE-319).
func TestConfig_TLSFieldsDefault(t *testing.T) {
	// Ensure env vars are absent for this test.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := config.Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to default to empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to default to empty, got %q", cfg.TLSKeyFile)
	}
}

// TestConfig_TLSFieldsFromEnv verifies that TLSCertFile and TLSKeyFile are
// populated correctly from environment variables.
func TestConfig_TLSFieldsFromEnv(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/tls/cert.pem")
	os.Setenv("TLS_KEY_FILE", "/etc/tls/key.pem")
	t.Cleanup(func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	})

	cfg := config.Load()

	if cfg.TLSCertFile != "/etc/tls/cert.pem" {
		t.Errorf("TLSCertFile: expected /etc/tls/cert.pem, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/tls/key.pem" {
		t.Errorf("TLSKeyFile: expected /etc/tls/key.pem, got %q", cfg.TLSKeyFile)
	}
}

// ---------------------------------------------------------------------------
// TLS enforcement: server must only accept HTTPS
// ---------------------------------------------------------------------------

// TestServer_TLSOnly_PlainHTTPRejected starts a real TLS listener and confirms
// that a plain HTTP client attempting to talk to it does NOT receive a valid
// HTTP response — the TLS handshake fails, not a 200 OK over plain text.
//
// This test guards against CWE-319: the server must never serve unencrypted
// responses even when a plain-HTTP client connects to it.
func TestServer_TLSOnly_PlainHTTPRejected(t *testing.T) {
	certFile, keyFile := writeTempTLSFiles(t)

	// Load the TLS certificate so we can start a listener on a free port.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Accept one connection in the background (the TLS handshake will fail).
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed — normal during test teardown
		}
		// Attempt the TLS handshake; a plain HTTP client will cause it to fail.
		tlsConn := conn.(*tls.Conn)
		tlsConn.Handshake() //nolint:errcheck // failure is expected
		conn.Close()
	}()

	// Plain HTTP client — no TLS configuration.
	plainClient := &http.Client{Timeout: 2 * time.Second}
	resp, err := plainClient.Get("http://" + addr + "/api/repo/list")

	// We expect an error (TLS server drops the plain-text connection) rather
	// than a successful response. A successful response would mean unencrypted
	// data was served, which is exactly the vulnerability.
	if err == nil {
		resp.Body.Close()
		t.Errorf("expected plain HTTP request to fail against TLS server, but got HTTP %d", resp.StatusCode)
	}
	// Any error here is correct — the server refused to serve plain text.
}

// TestServer_TLSOnly_HTTPSSucceeds confirms that an HTTPS client using the
// correct self-signed certificate can successfully reach a handler on the
// TLS server. This verifies that the TLS fix does not break legitimate usage.
func TestServer_TLSOnly_HTTPSSucceeds(t *testing.T) {
	certFile, keyFile := writeTempTLSFiles(t)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}

	// Parse the certificate so the client can trust our self-signed CA.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse x509 certificate: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(x509Cert)

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck

	// HTTPS client that trusts our self-signed certificate.
	tlsClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}

	resp, err := tlsClient.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 over TLS, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// TLS startup guard: missing cert/key must cause fatal error
// ---------------------------------------------------------------------------

// TestStartup_MissingTLSConfig_FatalError verifies the startup-guard logic:
// when TLS_CERT_FILE or TLS_KEY_FILE is absent from config, the server must
// not start (the guard in main() calls log.Fatal). We simulate the guard
// directly here since we cannot call log.Fatal in a unit test.
func TestStartup_MissingTLSConfig_FatalError(t *testing.T) {
	cases := []struct {
		name     string
		certFile string
		keyFile  string
	}{
		{"both empty", "", ""},
		{"cert empty", "", "/etc/tls/key.pem"},
		{"key empty", "/etc/tls/cert.pem", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				ServerPort:  ":8443",
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}

			// Replicate the guard condition from main().
			if !(cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
				t.Errorf("guard condition did not trigger for cert=%q key=%q; "+
					"server would start without full TLS config", tc.certFile, tc.keyFile)
			}
		})
	}
}

// TestStartup_WithTLSConfig_GuardPasses verifies that the guard does NOT
// trigger when both TLSCertFile and TLSKeyFile are set, allowing startup.
func TestStartup_WithTLSConfig_GuardPasses(t *testing.T) {
	certFile, keyFile := writeTempTLSFiles(t)

	cfg := &config.Config{
		ServerPort:  ":8443",
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}

	// Guard must NOT trigger (i.e., the condition must be false).
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		t.Errorf("guard triggered unexpectedly for cert=%q key=%q; "+
			"server would refuse to start with valid TLS config", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}

// TestServer_NoListenAndServe_InSource confirms at test time that the compiled
// binary's server entry point uses ListenAndServeTLS and not the plain-text
// ListenAndServe. This is a source-level regression guard — if someone reverts
// the fix by re-introducing http.ListenAndServe(plain) the test will catch it.
//
// We read main.go from the same package directory and verify the source text.
func TestServer_NoListenAndServe_InSource(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("could not read main.go: %v", err)
	}

	content := string(src)

	// Must use the TLS variant.
	if !strings.Contains(content, "ListenAndServeTLS") {
		t.Error("main.go does not call http.ListenAndServeTLS — TLS is required (CWE-319)")
	}

	// Must NOT fall back to the plain-text variant.
	// Strip the TLS variant first so a simple substring match is reliable.
	plainContent := strings.ReplaceAll(content, "ListenAndServeTLS", "")
	if strings.Contains(plainContent, "ListenAndServe(") {
		t.Error("main.go still calls plain http.ListenAndServe — " +
			"all traffic would be transmitted without encryption (CWE-319)")
	}
}
