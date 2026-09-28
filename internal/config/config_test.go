package config

import (
	"os"
	"testing"
)

// TestTLSEnabled verifies that TLSEnabled correctly reports whether TLS is configured.
func TestTLSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		want     bool
	}{
		{
			name:     "both cert and key set",
			certFile: "/path/to/cert.pem",
			keyFile:  "/path/to/key.pem",
			want:     true,
		},
		{
			name:     "only cert set",
			certFile: "/path/to/cert.pem",
			keyFile:  "",
			want:     false,
		},
		{
			name:     "only key set",
			certFile: "",
			keyFile:  "/path/to/key.pem",
			want:     false,
		},
		{
			name:     "neither cert nor key set",
			certFile: "",
			keyFile:  "",
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}
			got := cfg.TLSEnabled()
			if got != tc.want {
				t.Errorf("TLSEnabled() = %v, want %v (certFile=%q, keyFile=%q)",
					got, tc.want, tc.certFile, tc.keyFile)
			}
		})
	}
}

// TestLoadTLSFromEnvironment verifies that Load reads TLS paths from env variables.
func TestLoadTLSFromEnvironment(t *testing.T) {
	// Save and restore original env values.
	origCert := os.Getenv("TLS_CERT_FILE")
	origKey := os.Getenv("TLS_KEY_FILE")
	defer func() {
		os.Setenv("TLS_CERT_FILE", origCert)
		os.Setenv("TLS_KEY_FILE", origKey)
	}()

	os.Setenv("TLS_CERT_FILE", "/etc/tls/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/tls/server.key")

	cfg := Load()

	if cfg.TLSCertFile != "/etc/tls/server.crt" {
		t.Errorf("TLSCertFile = %q, want %q", cfg.TLSCertFile, "/etc/tls/server.crt")
	}
	if cfg.TLSKeyFile != "/etc/tls/server.key" {
		t.Errorf("TLSKeyFile = %q, want %q", cfg.TLSKeyFile, "/etc/tls/server.key")
	}
	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled() = false, want true when both cert and key are set")
	}
}

// TestLoadTLSDefaultsToEmpty verifies that TLS paths are empty strings by default,
// meaning the server will refuse to start without explicit TLS configuration.
// This is the security-critical behaviour introduced to fix CWE-319.
func TestLoadTLSDefaultsToEmpty(t *testing.T) {
	// Ensure both env vars are unset.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile default = %q, want empty string", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile default = %q, want empty string", cfg.TLSKeyFile)
	}
	// When TLS is not configured the server should refuse to start (TLSEnabled false).
	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true, want false when env vars are not set")
	}
}

// TestLoadServerPort verifies that SERVER_PORT is read from the environment,
// with a sensible default when not set.
func TestLoadServerPort(t *testing.T) {
	origPort := os.Getenv("SERVER_PORT")
	defer os.Setenv("SERVER_PORT", origPort)

	os.Unsetenv("SERVER_PORT")
	cfg := Load()
	if cfg.ServerPort != ":8081" {
		t.Errorf("default ServerPort = %q, want %q", cfg.ServerPort, ":8081")
	}

	os.Setenv("SERVER_PORT", ":9443")
	cfg = Load()
	if cfg.ServerPort != ":9443" {
		t.Errorf("ServerPort = %q, want %q", cfg.ServerPort, ":9443")
	}
}
