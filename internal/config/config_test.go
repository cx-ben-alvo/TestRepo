package config

import (
	"os"
	"testing"
)

// TestLoadDefaults verifies that Config.Load returns sensible defaults
// and that the TLS fields default to empty strings (no plain-text fallback).
func TestLoadDefaults(t *testing.T) {
	// Clear TLS env vars so we test true defaults.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("ServerPort must not be empty")
	}

	// TLS cert/key default to empty string — the server must not start
	// without them being explicitly configured; there is no insecure fallback.
	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile default should be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile default should be empty, got %q", cfg.TLSKeyFile)
	}
}

// TestLoadTLSFromEnv verifies that TLS cert and key paths are read from the
// TLS_CERT_FILE and TLS_KEY_FILE environment variables (CWE-319 remediation).
func TestLoadTLSFromEnv(t *testing.T) {
	wantCert := "/etc/ssl/server.crt"
	wantKey := "/etc/ssl/server.key"

	t.Setenv("TLS_CERT_FILE", wantCert)
	t.Setenv("TLS_KEY_FILE", wantKey)

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: want %q, got %q", wantCert, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: want %q, got %q", wantKey, cfg.TLSKeyFile)
	}
}

// TestLoadServerPortFromEnv verifies that the server port is read from
// the SERVER_PORT environment variable.
func TestLoadServerPortFromEnv(t *testing.T) {
	want := ":9443"
	t.Setenv("SERVER_PORT", want)

	cfg := Load()

	if cfg.ServerPort != want {
		t.Errorf("ServerPort: want %q, got %q", want, cfg.ServerPort)
	}
}

// TestConfigHasTLSFields ensures the Config struct exposes TLSCertFile and
// TLSKeyFile — a compile-time guard that the fields are never removed.
func TestConfigHasTLSFields(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}

	if cfg.TLSCertFile == "" {
		t.Error("Config must have a TLSCertFile field")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("Config must have a TLSKeyFile field")
	}
}
