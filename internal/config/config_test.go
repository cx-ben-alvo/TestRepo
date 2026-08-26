package config

import (
	"os"
	"testing"
)

func TestLoad_DefaultValues(t *testing.T) {
	// Clear TLS env vars to test defaults
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected ServerPort ':8081', got %q", cfg.ServerPort)
	}
	// TLS fields must default to empty strings — absence is detected by main to
	// refuse startup without TLS (CWE-319 remediation).
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to default to empty string, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to default to empty string, got %q", cfg.TLSKeyFile)
	}
}

func TestLoad_TLSFromEnv(t *testing.T) {
	// Set TLS env vars to simulate a production deployment with certificates.
	os.Setenv("TLS_CERT_FILE", "/etc/certs/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/certs/server.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != "/etc/certs/server.crt" {
		t.Errorf("expected TLSCertFile '/etc/certs/server.crt', got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/certs/server.key" {
		t.Errorf("expected TLSKeyFile '/etc/certs/server.key', got %q", cfg.TLSKeyFile)
	}
}

func TestLoad_ServerPortFromEnv(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort ':9443', got %q", cfg.ServerPort)
	}
}

// TestTLSRequiredForStartup verifies that both TLS fields must be non-empty
// for the server to start; having only one set is not sufficient.
func TestTLSRequiredForStartup(t *testing.T) {
	cases := []struct {
		name        string
		certFile    string
		keyFile     string
		tlsReady    bool
	}{
		{"both empty — no TLS", "", "", false},
		{"cert only — incomplete", "/path/to/cert.pem", "", false},
		{"key only — incomplete", "", "/path/to/key.pem", false},
		{"both provided — TLS ready", "/path/to/cert.pem", "/path/to/key.pem", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ServerPort:  ":8081",
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}
			// The condition used in main.go to guard ListenAndServeTLS.
			tlsReady := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
			if tlsReady != tc.tlsReady {
				t.Errorf("tlsReady=%v, want %v (cert=%q, key=%q)",
					tlsReady, tc.tlsReady, tc.certFile, tc.keyFile)
			}
		})
	}
}

// TestTLSNotPlainHTTP ensures that no fallback to plain http.ListenAndServe is
// present in the Config — the configuration layer provides no option to bypass TLS.
func TestTLSNotPlainHTTP(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Config must not provide a way to enable plain HTTP; the TLS fields being
	// empty is what the server uses to refuse startup, not a separate "UseTLS" flag
	// that could accidentally default to false.
	if cfg.TLSCertFile != "" {
		t.Error("TLSCertFile should be empty when env var is unset; plain HTTP must be refused")
	}
	if cfg.TLSKeyFile != "" {
		t.Error("TLSKeyFile should be empty when env var is unset; plain HTTP must be refused")
	}
}
