package config

import (
	"os"
	"testing"
)

// TestLoadTLSFields verifies that TLS certificate and key paths are loaded
// from environment variables, ensuring the server can be configured for HTTPS.
func TestLoadTLSFields(t *testing.T) {
	const certPath = "/etc/tls/server.crt"
	const keyPath = "/etc/tls/server.key"

	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("expected TLSCertFile %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("expected TLSKeyFile %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoadTLSDefaultsAreEmpty verifies that TLS paths default to empty strings
// when the environment variables are not set. An empty value signals that TLS
// configuration is missing and must be supplied before the server starts.
func TestLoadTLSDefaultsAreEmpty(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty TLSCertFile by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty TLSKeyFile by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoadServerPort verifies that SERVER_PORT is loaded from the environment.
func TestLoadServerPort(t *testing.T) {
	t.Setenv("SERVER_PORT", ":9443")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort %q, got %q", ":9443", cfg.ServerPort)
	}
}

// TestLoadServerPortDefault verifies the default server port when the
// environment variable is absent.
func TestLoadServerPortDefault(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort %q, got %q", ":8081", cfg.ServerPort)
	}
}
