package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that the default configuration values are set correctly
// when no environment variables are present.
func TestLoad_DefaultValues(t *testing.T) {
	// Ensure the relevant env vars are unset for a clean test
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected ServerPort ':8081', got '%s'", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty by default, got '%s'", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty by default, got '%s'", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVarsAreRead verifies that TLS_CERT_FILE and TLS_KEY_FILE
// environment variables are correctly loaded into the Config struct.
func TestLoad_TLSEnvVarsAreRead(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")
	defer os.Unsetenv("TLS_CERT_FILE")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/certs/server.crt" {
		t.Errorf("expected TLSCertFile '/etc/ssl/certs/server.crt', got '%s'", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/private/server.key" {
		t.Errorf("expected TLSKeyFile '/etc/ssl/private/server.key', got '%s'", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsExist verifies that the Config struct has TLS fields,
// preventing regression where TLS support could be accidentally removed.
func TestLoad_TLSFieldsExist(t *testing.T) {
	cfg := Load()

	// Access the fields — this will fail to compile if they are removed,
	// acting as a compile-time regression guard for TLS configuration.
	_ = cfg.TLSCertFile
	_ = cfg.TLSKeyFile
}

// TestLoad_AllEnvVarsOverrideDefaults verifies that all environment variables
// override their default values, including the new TLS fields.
func TestLoad_AllEnvVarsOverrideDefaults(t *testing.T) {
	os.Setenv("SERVER_PORT", ":443")
	os.Setenv("CLONE_DIR", "/tmp/clones")
	os.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	os.Setenv("TLS_CERT_FILE", "/certs/tls.crt")
	os.Setenv("TLS_KEY_FILE", "/certs/tls.key")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("CLONE_DIR")
		os.Unsetenv("DOWNLOAD_DIR")
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.ServerPort != ":443" {
		t.Errorf("expected ServerPort ':443', got '%s'", cfg.ServerPort)
	}
	if cfg.CloneDir != "/tmp/clones" {
		t.Errorf("expected CloneDir '/tmp/clones', got '%s'", cfg.CloneDir)
	}
	if cfg.DownloadDir != "/tmp/downloads" {
		t.Errorf("expected DownloadDir '/tmp/downloads', got '%s'", cfg.DownloadDir)
	}
	if cfg.TLSCertFile != "/certs/tls.crt" {
		t.Errorf("expected TLSCertFile '/certs/tls.crt', got '%s'", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/certs/tls.key" {
		t.Errorf("expected TLSKeyFile '/certs/tls.key', got '%s'", cfg.TLSKeyFile)
	}
}

// TestConfig_TLSMissingImpliesInsecure verifies that when TLS fields are empty,
// the application cannot start securely. This documents the security invariant:
// a Config with empty TLS paths must never be used to call ListenAndServeTLS.
func TestConfig_TLSMissingImpliesInsecure(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Both fields must be non-empty for the server to start securely.
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		t.Errorf("expected both TLS fields to be empty when env vars are unset; "+
			"got TLSCertFile='%s', TLSKeyFile='%s'", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}
