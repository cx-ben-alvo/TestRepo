package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that Load returns built-in defaults when no
// environment variables are set.
func TestLoad_Defaults(t *testing.T) {
	// Ensure relevant env vars are unset for this test.
	for _, key := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
		os.Unsetenv(key)
	}

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("expected a non-empty default ServerPort")
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to default to empty string, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to default to empty string, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_EnvOverrides verifies that environment variables override defaults.
func TestLoad_EnvOverrides(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	os.Setenv("TLS_CERT_FILE", "/etc/tls/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/tls/server.key")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort :9443, got %q", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "/etc/tls/server.crt" {
		t.Errorf("expected TLSCertFile /etc/tls/server.crt, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/tls/server.key" {
		t.Errorf("expected TLSKeyFile /etc/tls/server.key, got %q", cfg.TLSKeyFile)
	}
}

// TestTLSEnabled_BothSet verifies that TLSEnabled returns true when both cert
// and key are provided, confirming that the server is configured to use TLS
// (HTTPS) rather than plain HTTP (CWE-319 remediation).
func TestTLSEnabled_BothSet(t *testing.T) {
	cfg := &Config{
		ServerPort:  ":8443",
		TLSCertFile: "/etc/tls/server.crt",
		TLSKeyFile:  "/etc/tls/server.key",
	}
	if !cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() to return true when both TLSCertFile and TLSKeyFile are set")
	}
}

// TestTLSEnabled_OnlyCert verifies that TLSEnabled returns false when only
// the certificate is set (the key is missing).
func TestTLSEnabled_OnlyCert(t *testing.T) {
	cfg := &Config{
		ServerPort:  ":8443",
		TLSCertFile: "/etc/tls/server.crt",
		TLSKeyFile:  "",
	}
	if cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() to return false when TLSKeyFile is empty")
	}
}

// TestTLSEnabled_OnlyKey verifies that TLSEnabled returns false when only
// the key is set (the certificate is missing).
func TestTLSEnabled_OnlyKey(t *testing.T) {
	cfg := &Config{
		ServerPort:  ":8443",
		TLSCertFile: "",
		TLSKeyFile:  "/etc/tls/server.key",
	}
	if cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() to return false when TLSCertFile is empty")
	}
}

// TestTLSEnabled_NeitherSet verifies that TLSEnabled returns false when
// neither cert nor key is provided, meaning the server falls back to plain
// HTTP. This is the default (development/unconfigured) state.
func TestTLSEnabled_NeitherSet(t *testing.T) {
	cfg := &Config{
		ServerPort:  ":8081",
		TLSCertFile: "",
		TLSKeyFile:  "",
	}
	if cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() to return false when both TLSCertFile and TLSKeyFile are empty")
	}
}

// TestLoad_TLSDisabledByDefault verifies that the built-in defaults do NOT
// enable TLS, ensuring the server does not crash on startup due to missing
// certificate files when running without explicit TLS configuration.
func TestLoad_TLSDisabledByDefault(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSEnabled() {
		t.Error("expected TLS to be disabled by default (no cert/key env vars set)")
	}
}

// TestLoad_TLSEnabledWhenEnvVarsSet verifies that loading config with both
// TLS environment variables set correctly enables TLS mode.
func TestLoad_TLSEnabledWhenEnvVarsSet(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/run/secrets/tls.crt")
	os.Setenv("TLS_KEY_FILE", "/run/secrets/tls.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if !cfg.TLSEnabled() {
		t.Error("expected TLS to be enabled when TLS_CERT_FILE and TLS_KEY_FILE env vars are set")
	}
}
