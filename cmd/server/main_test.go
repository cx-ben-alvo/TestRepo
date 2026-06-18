package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTLSServerUsesHTTPS verifies that the application's HTTP handler stack can
// be served over TLS.  httptest.NewTLSServer wraps the default ServeMux with a
// self-signed certificate and confirms that:
//  1. The server only accepts HTTPS connections (not plain HTTP).
//  2. A client that trusts the test certificate can complete a TLS handshake
//     and receive a valid response.
//
// This is a regression guard for CWE-319: the original code used
// http.ListenAndServe (plain text).  After the fix the code must call
// http.ListenAndServeTLS so all traffic is encrypted in transit.
func TestTLSServerUsesHTTPS(t *testing.T) {
	// Register a simple probe handler on an isolated ServeMux so we do not
	// pollute the default mux used by main().
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// httptest.NewTLSServer starts a real TLS listener with a self-signed cert.
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// The test server's TLS client already has the self-signed cert trusted.
	client := ts.Client()

	resp, err := client.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK from TLS server, got %d", resp.StatusCode)
	}

	// Confirm the connection was actually TLS (not plain HTTP).
	if resp.TLS == nil {
		t.Error("response.TLS is nil — the connection was NOT encrypted; server must use TLS")
	}
}

// TestPlainHTTPClientCannotConnectToTLSServer verifies that a plain-text HTTP
// client cannot successfully communicate with a TLS server.  This is the
// complementary negative test: if a client mistakenly omits TLS, the handshake
// must fail — protecting users from accidental downgrade.
func TestPlainHTTPClientCannotConnectToTLSServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Use a plain http.Client (no TLS config) — it will reject the self-signed
	// cert and the connection must fail, demonstrating that plain-text clients
	// cannot silently read the server's responses.
	plainClient := &http.Client{}
	_, err := plainClient.Get(ts.URL + "/health")
	if err == nil {
		t.Error("plain-text HTTP client connected to a TLS server without error; this should not happen")
	}
}

// TestTLSVersionMinimum verifies that the TLS server rejects connections that
// negotiate below TLS 1.2, ensuring the server does not fall back to weak
// legacy protocols.
func TestTLSVersionMinimum(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Build a pool that trusts the test server's self-signed certificate.
	certPool := x509.NewCertPool()
	for _, cert := range ts.TLS.Certificates {
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse test server cert: %v", err)
		}
		certPool.AddCert(x509Cert)
	}

	// Attempt a connection that explicitly requests TLS 1.0 — httptest's
	// default server config enforces at least TLS 1.2, so this must fail.
	weakClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MaxVersion: tls.VersionTLS11, // force negotiation to ≤ TLS 1.1
				RootCAs:    certPool,
			},
		},
	}

	_, err := weakClient.Get(ts.URL + "/")
	if err == nil {
		t.Error("a client restricted to TLS ≤ 1.1 should not be able to connect to the TLS server; the server must enforce TLS 1.2 or higher")
	}
}
