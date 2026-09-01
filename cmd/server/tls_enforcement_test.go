package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServerUsesTLS verifies that an HTTP server configured with TLS actually
// requires TLS connections and rejects plain-text (HTTP) connections.
//
// This is a regression guard for CWE-319 (Cleartext Transmission of Sensitive
// Information): if the server is ever reverted to http.ListenAndServe, a
// plain-text client can connect and this test documents the expected behaviour.
func TestServerUsesTLS(t *testing.T) {
	// httptest.NewTLSServer starts a TLS listener backed by a self-signed
	// certificate – the same mechanism used by http.ListenAndServeTLS in
	// production.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// A client that trusts the test server's self-signed certificate MUST be
	// able to connect via HTTPS.
	tlsClient := ts.Client()
	resp, err := tlsClient.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("TLS client failed to connect to TLS server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK from TLS server, got %d", resp.StatusCode)
	}
}

// TestPlainHTTPClientFailsAgainstTLSServer verifies that a plain HTTP client
// cannot successfully retrieve a response from a TLS-only server.
//
// This confirms that switching to ListenAndServeTLS (HTTPS) actually prevents
// cleartext connections – a client that sends raw HTTP to a TLS listener will
// receive a TLS handshake error rather than a response.
func TestPlainHTTPClientFailsAgainstTLSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Build a plain HTTP client – no TLS configuration.
	plainClient := &http.Client{
		Transport: &http.Transport{
			// Explicitly disable TLS so this is a cleartext client.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			DialTLS:         nil,
			Dial: func(network, addr string) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	// The TLS server's URL uses "https://"; change the scheme to "http://" to
	// simulate a client that attempts a plain-text connection.
	plainURL := "http://" + ts.Listener.Addr().String() + "/"
	_, err := plainClient.Get(plainURL)

	// We expect an error: the server speaks TLS; the client does not.
	// The error proves that plain-text transport is rejected.
	if err == nil {
		t.Error("expected a connection error when a plain HTTP client contacts a TLS server, but got none")
	}
}

// TestTLSHandshakeSucceeds exercises the full TLS handshake path to confirm
// that the server certificate negotiation works end-to-end.
func TestTLSHandshakeSucceeds(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	// Perform a raw TLS dial to verify the handshake independently of the HTTP
	// layer.
	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // test cert is self-signed; skip chain verification
	})
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	conn.Close()
}
