package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that the default configuration is populated
// correctly when no environment variables are set.
func TestLoad_DefaultValues(t *testing.T) {
	// Ensure env vars are unset so we get defaults.
	for _, key := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
		os.Unsetenv(key)
	}

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected ServerPort ':8081', got %q", cfg.ServerPort)
	}
	if cfg.CloneDir != "/Users/benalvo/clones" {
		t.Errorf("expected default CloneDir, got %q", cfg.CloneDir)
	}
	if cfg.DownloadDir != "/Users/benalvo/downloads" {
		t.Errorf("expected default DownloadDir, got %q", cfg.DownloadDir)
	}
}

// TestLoad_TLSFieldsDefaultToEmpty verifies that TLSCertFile and TLSKeyFile
// default to empty strings when the environment variables are not set.
// An empty value means the server will fail to start unless valid paths are
// supplied, which is the secure-by-default behaviour (no plain-text fallback).
func TestLoad_TLSFieldsDefaultToEmpty(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile should default to empty string, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile should default to empty string, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLSCertFile and TLSKeyFile are
// correctly loaded from the TLS_CERT_FILE / TLS_KEY_FILE environment variables.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/tls/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/tls/server.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != "/etc/tls/server.crt" {
		t.Errorf("expected TLSCertFile '/etc/tls/server.crt', got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/tls/server.key" {
		t.Errorf("expected TLSKeyFile '/etc/tls/server.key', got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_AllFieldsFromEnv verifies that every configuration value can be
// overridden via environment variables.
func TestLoad_AllFieldsFromEnv(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	os.Setenv("CLONE_DIR", "/tmp/clones")
	os.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	os.Setenv("TLS_CERT_FILE", "/tmp/cert.pem")
	os.Setenv("TLS_KEY_FILE", "/tmp/key.pem")
	defer func() {
		for _, key := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
			os.Unsetenv(key)
		}
	}()

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort ':9443', got %q", cfg.ServerPort)
	}
	if cfg.CloneDir != "/tmp/clones" {
		t.Errorf("expected CloneDir '/tmp/clones', got %q", cfg.CloneDir)
	}
	if cfg.DownloadDir != "/tmp/downloads" {
		t.Errorf("expected DownloadDir '/tmp/downloads', got %q", cfg.DownloadDir)
	}
	if cfg.TLSCertFile != "/tmp/cert.pem" {
		t.Errorf("expected TLSCertFile '/tmp/cert.pem', got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/tmp/key.pem" {
		t.Errorf("expected TLSKeyFile '/tmp/key.pem', got %q", cfg.TLSKeyFile)
	}
}

// TestConfig_HasTLSFields is a compile-time guard: it asserts that the Config
// struct exposes TLSCertFile and TLSKeyFile fields so that the server can be
// configured to use TLS.  If either field is ever removed, this test will fail
// to compile, catching accidental regression to plain-HTTP transport.
func TestConfig_HasTLSFields(t *testing.T) {
	var cfg Config
	// Assign the fields – if they don't exist the compiler will reject this.
	cfg.TLSCertFile = "cert.pem"
	cfg.TLSKeyFile = "key.pem"

	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		t.Error("TLSCertFile and TLSKeyFile must be non-empty after assignment")
	}
}
