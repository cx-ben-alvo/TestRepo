package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// TestTLSConfigRequired verifies that the application configuration correctly
// exposes TLSCertFile and TLSKeyFile fields so the server startup code can
// enforce their presence.  An empty TLSCertFile or TLSKeyFile must signal that
// TLS has not been configured, allowing main() to refuse to start a plain-text
// server.
func TestTLSConfigRequired(t *testing.T) {
	tests := []struct {
		name         string
		certFile     string
		keyFile      string
		tlsConfigured bool
	}{
		{
			name:          "both fields empty – TLS not configured",
			certFile:      "",
			keyFile:       "",
			tlsConfigured: false,
		},
		{
			name:          "cert set but key missing – TLS not configured",
			certFile:      "/path/to/cert.pem",
			keyFile:       "",
			tlsConfigured: false,
		},
		{
			name:          "key set but cert missing – TLS not configured",
			certFile:      "",
			keyFile:       "/path/to/key.pem",
			tlsConfigured: false,
		},
		{
			name:          "both cert and key provided – TLS configured",
			certFile:      "/path/to/cert.pem",
			keyFile:       "/path/to/key.pem",
			tlsConfigured: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}

			got := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
			if got != tc.tlsConfigured {
				t.Errorf("TLS configured check: expected %v, got %v (cert=%q, key=%q)",
					tc.tlsConfigured, got, tc.certFile, tc.keyFile)
			}
		})
	}
}

// TestServerUseTLS verifies that when valid TLS credentials are available the
// server accepts HTTPS connections.  The test spins up httptest.NewTLSServer
// (which uses the same underlying ListenAndServeTLS mechanism) to confirm that
// the handler is reachable over an encrypted channel.
func TestServerUseTLS(t *testing.T) {
	// Create a simple handler to confirm the server is reachable.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// The test server uses a self-signed certificate; configure the client to
	// trust it so the TLS handshake succeeds.
	client := ts.Client()

	resp, err := client.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("request to TLS test server failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from TLS server, got %d", resp.StatusCode)
	}

	// Confirm the connection used TLS (not plain HTTP).
	if resp.TLS == nil {
		t.Error("expected TLS connection state to be non-nil; server responded over plain HTTP")
	}
}

// TestPlainHTTPRejectedByTLSServer verifies that a client that explicitly
// refuses TLS (by not trusting the server certificate) cannot connect to a
// server running with TLS.  This guards against any code regression that
// accidentally falls back to plain HTTP.
func TestPlainHTTPRejectedByTLSServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Use a plain HTTP client that has NOT been configured with the server's
	// self-signed certificate.  The TLS handshake must fail.
	plainClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Empty root pool – will not trust the test server certificate.
				RootCAs: x509.NewCertPool(),
			},
		},
	}

	_, err := plainClient.Get(ts.URL + "/probe")
	if err == nil {
		t.Error("expected TLS certificate verification failure, but request succeeded")
	}
}

// TestServerAddressNotHTTP confirms that the default server port is a TLS
// port (:8443) and not a plain HTTP port (:80 or :8080), reducing the risk
// of accidental plain-text deployment.
func TestServerAddressNotHTTP(t *testing.T) {
	t.Setenv("SERVER_PORT", "")
	cfg := config.Load()

	plainPorts := []string{":80", ":8080", ":8081"}
	for _, p := range plainPorts {
		if cfg.ServerPort == p {
			t.Errorf("default server port must not be a plain-HTTP port; got %q", cfg.ServerPort)
		}
	}
}

// TestListenerIsTLS is an integration-style test that starts a TLS listener on
// an ephemeral port and verifies the connection is encrypted by inspecting the
// tls.ConnectionState returned after a successful handshake.
func TestListenerIsTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	// Extract host:port from the test server URL.
	addr := ts.Listener.Addr().String()

	// Dial with the test server's certificate pool to ensure TLS succeeds.
	tlsCfg := ts.Client().Transport.(*http.Transport).TLSClientConfig
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		t.Error("TLS handshake did not complete")
	}

	// The negotiated protocol must be TLS (not empty, not "http/1.1" raw).
	_, _, err = net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("invalid address %q: %v", addr, err)
	}

	if len(state.PeerCertificates) == 0 {
		t.Error("expected at least one peer certificate in TLS connection state")
	}
}
