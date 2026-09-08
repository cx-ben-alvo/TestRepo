package config

import (
	"os"
	"testing"
)

// TestLoadDefaultsTLSFieldsEmpty verifies that TLS cert/key fields default to
// empty strings when the corresponding environment variables are not set.
// An empty TLS configuration is intentional (it must be rejected at startup),
// but the Load() function itself must not silently supply insecure defaults.
func TestLoadDefaultsTLSFieldsEmpty(t *testing.T) {
	// Ensure the TLS env vars are absent for this test.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoadTLSFieldsFromEnv verifies that TLS cert and key paths are read from
// environment variables so that production deployments can supply them without
// code changes.
func TestLoadTLSFieldsFromEnv(t *testing.T) {
	const certPath = "/etc/ssl/certs/server.crt"
	const keyPath = "/etc/ssl/private/server.key"

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

// TestLoadServerPortDefault verifies the default server port is still loaded
// correctly after the TLS fields were added (regression guard).
func TestLoadServerPortDefault(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort :8081, got %q", cfg.ServerPort)
	}
}

// TestLoadServerPortFromEnv verifies that the server port is overridable via
// environment variable (regression guard for existing functionality).
func TestLoadServerPortFromEnv(t *testing.T) {
	t.Setenv("SERVER_PORT", ":9443")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort :9443, got %q", cfg.ServerPort)
	}
}

// TestTLSRequiredForServer documents the expected startup behaviour: when both
// TLS_CERT_FILE and TLS_KEY_FILE are empty the server must refuse to start
// rather than fall back to plain-text HTTP.
// This test validates the config state that main.go checks at startup.
func TestTLSRequiredForServer(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Both fields must be non-empty for a TLS-enabled server to start.
	// main.go calls log.Fatal when either is empty, enforcing HTTPS-only.
	tlsConfigured := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if tlsConfigured {
		t.Error("expected TLS to be unconfigured when env vars are absent; " +
			"plain-text fallback must not be silently introduced")
	}
}
