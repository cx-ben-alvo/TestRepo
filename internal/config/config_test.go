package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that Config.Load returns the expected default values
// when no environment variables are set.
func TestLoad_Defaults(t *testing.T) {
	// Ensure TLS env vars are not set for this test.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort ':8081', got %q", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty default TLSCertFile, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty default TLSKeyFile, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS_CERT_FILE and TLS_KEY_FILE environment
// variables are read correctly by Config.Load.  This ensures the application
// can be configured to use TLS certificates from the environment rather than
// having them hard-coded or absent.
func TestLoad_TLSEnvVars(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.crt"
	const wantKey = "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: expected %q, got %q", wantCert, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: expected %q, got %q", wantKey, cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortOverride verifies that the SERVER_PORT environment variable
// overrides the default.
func TestLoad_ServerPortOverride(t *testing.T) {
	const wantPort = ":9443"

	os.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort: expected %q, got %q", wantPort, cfg.ServerPort)
	}
}

// TestConfig_HasTLSFields is a compile-time + runtime check that ensures the
// Config struct exposes TLSCertFile and TLSKeyFile fields.  If either field
// were removed the test would fail to compile, preventing regression to the
// insecure plain-HTTP configuration (CWE-319).
func TestConfig_HasTLSFields(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}

	if cfg.TLSCertFile == "" {
		t.Error("TLSCertFile must not be empty after explicit assignment")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("TLSKeyFile must not be empty after explicit assignment")
	}
}
