package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that Load returns sensible defaults when no
// environment variables are set.
func TestLoad_Defaults(t *testing.T) {
	// Clear all relevant env vars to ensure we test defaults.
	for _, key := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
		os.Unsetenv(key)
	}

	cfg := Load()

	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort :8443, got %q", cfg.ServerPort)
	}
	// TLS fields must default to empty string so the server startup code can
	// detect that TLS has NOT been configured and refuse to start.
	if cfg.TLSCertFile != "" {
		t.Errorf("expected default TLSCertFile to be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected default TLSKeyFile to be empty, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS_CERT_FILE and TLS_KEY_FILE are read
// from environment variables and stored in the Config struct.
func TestLoad_TLSEnvVars(t *testing.T) {
	const certFile = "/etc/ssl/certs/server.crt"
	const keyFile = "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", certFile)
	os.Setenv("TLS_KEY_FILE", keyFile)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != certFile {
		t.Errorf("expected TLSCertFile %q, got %q", certFile, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyFile {
		t.Errorf("expected TLSKeyFile %q, got %q", keyFile, cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortOverride verifies that SERVER_PORT env var overrides the
// default value.
func TestLoad_ServerPortOverride(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort :9443, got %q", cfg.ServerPort)
	}
}

// TestLoad_TLSFieldsPresent verifies that the Config struct exposes TLS
// configuration fields (regression guard: fields must not be removed).
func TestLoad_TLSFieldsPresent(t *testing.T) {
	cfg := Load()
	// Access fields to ensure they exist — compilation failure here means the
	// TLS configuration was inadvertently removed from the struct.
	_ = cfg.TLSCertFile
	_ = cfg.TLSKeyFile
}

// TestLoad_NoTLSByDefault verifies that TLS is NOT configured by default,
// which forces operators to explicitly provide certificate paths before the
// server will start (defence-in-depth: prevents accidental plain-HTTP startup
// with empty but non-empty default paths).
func TestLoad_NoTLSByDefault(t *testing.T) {
	for _, key := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE"} {
		os.Unsetenv(key)
	}

	cfg := Load()

	// Both paths being empty is the signal that TLS has not been configured;
	// the server startup code checks this and refuses to start without TLS.
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		t.Errorf(
			"expected both TLS paths to be empty when env vars are unset; got cert=%q key=%q",
			cfg.TLSCertFile, cfg.TLSKeyFile,
		)
	}
}
