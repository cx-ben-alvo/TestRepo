package config

import (
	"os"
	"testing"
)

// TestLoadDefaults verifies that the default configuration values are set correctly.
func TestLoadDefaults(t *testing.T) {
	// Clear any environment variables that might interfere
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("ServerPort should have a default value")
	}
	if cfg.TLSCertFile == "" {
		t.Error("TLSCertFile should have a default value; server must not start without TLS")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("TLSKeyFile should have a default value; server must not start without TLS")
	}
}

// TestLoadTLSFromEnv verifies that TLS cert/key paths can be overridden via
// environment variables so that deployments can supply production certificates.
func TestLoadTLSFromEnv(t *testing.T) {
	const wantCert = "/run/secrets/tls/server.crt"
	const wantKey = "/run/secrets/tls/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile = %q, want %q", cfg.TLSCertFile, wantCert)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile = %q, want %q", cfg.TLSKeyFile, wantKey)
	}
}

// TestLoadServerPortFromEnv verifies that SERVER_PORT is read from the environment.
func TestLoadServerPortFromEnv(t *testing.T) {
	const wantPort = ":9443"
	os.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()
	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort = %q, want %q", cfg.ServerPort, wantPort)
	}
}

// TestTLSFieldsAreSeparate ensures cert and key paths are stored independently
// so that they cannot be accidentally swapped.
func TestTLSFieldsAreSeparate(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "my-cert.pem")
	os.Setenv("TLS_KEY_FILE", "my-key.pem")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile == cfg.TLSKeyFile {
		t.Error("TLSCertFile and TLSKeyFile must not be equal; they serve different roles")
	}
}
