package config

import (
	"os"
	"testing"
)

// TestLoadDefaultConfig verifies that the default configuration has empty TLS fields,
// requiring operators to explicitly set TLS_CERT_FILE and TLS_KEY_FILE.
func TestLoadDefaultConfig(t *testing.T) {
	// Ensure TLS env vars are not set for this test
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty default TLSCertFile, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty default TLSKeyFile, got %q", cfg.TLSKeyFile)
	}
}

// TestLoadTLSConfigFromEnv verifies that TLS certificate and key paths are read from
// environment variables, ensuring the server can be configured for HTTPS.
func TestLoadTLSConfigFromEnv(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/certs/server.crt" {
		t.Errorf("expected TLSCertFile %q, got %q", "/etc/ssl/certs/server.crt", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/private/server.key" {
		t.Errorf("expected TLSKeyFile %q, got %q", "/etc/ssl/private/server.key", cfg.TLSKeyFile)
	}
}

// TestLoadServerPort verifies that the server port is read from the environment variable.
func TestLoadServerPort(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()
	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort %q, got %q", ":9443", cfg.ServerPort)
	}
}

// TestConfigHasTLSFields verifies that the Config struct exposes TLS certificate and
// key fields, which are required for starting a TLS-secured server.
func TestConfigHasTLSFields(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}
	if cfg.TLSCertFile == "" {
		t.Error("Config.TLSCertFile must be settable")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("Config.TLSKeyFile must be settable")
	}
}
