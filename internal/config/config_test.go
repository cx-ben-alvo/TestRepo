package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that default values are used when no
// environment variables are set.
func TestLoad_DefaultValues(t *testing.T) {
	// Ensure none of the environment variables are set.
	unsetEnvVars(t, "SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected ServerPort ':8081', got %q", cfg.ServerPort)
	}
	// TLS fields must default to empty strings — the caller (main) is
	// responsible for rejecting an empty TLS configuration at startup.
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS_CERT_FILE and TLS_KEY_FILE are read
// from environment variables.
func TestLoad_TLSEnvVars(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/certs/server.crt" {
		t.Errorf("expected TLSCertFile '/etc/ssl/certs/server.crt', got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/private/server.key" {
		t.Errorf("expected TLSKeyFile '/etc/ssl/private/server.key', got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_PartialTLSConfig verifies that when only one TLS variable is set,
// the other remains empty — main must catch this and refuse to start.
func TestLoad_PartialTLSConfig(t *testing.T) {
	unsetEnvVars(t, "TLS_KEY_FILE")
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")

	cfg := Load()

	if cfg.TLSCertFile == "" {
		t.Error("expected TLSCertFile to be set")
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty when TLS_KEY_FILE is not set, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_AllEnvVars verifies all configuration fields are read from
// environment variables.
func TestLoad_AllEnvVars(t *testing.T) {
	t.Setenv("SERVER_PORT", ":9443")
	t.Setenv("CLONE_DIR", "/tmp/clones")
	t.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	t.Setenv("TLS_CERT_FILE", "/certs/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/certs/tls.key")

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
	if cfg.TLSCertFile != "/certs/tls.crt" {
		t.Errorf("expected TLSCertFile '/certs/tls.crt', got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/certs/tls.key" {
		t.Errorf("expected TLSKeyFile '/certs/tls.key', got %q", cfg.TLSKeyFile)
	}
}

// TestTLSFieldsPresent verifies that the Config struct exposes TLSCertFile and
// TLSKeyFile fields (compile-time check that the struct definition is correct).
func TestTLSFieldsPresent(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}
	if cfg.TLSCertFile != "cert.pem" {
		t.Errorf("TLSCertFile field missing or inaccessible")
	}
	if cfg.TLSKeyFile != "key.pem" {
		t.Errorf("TLSKeyFile field missing or inaccessible")
	}
}

// unsetEnvVars unregisters the given environment variables for the duration of
// the test and restores them automatically via t.Cleanup.
func unsetEnvVars(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		prev, existed := os.LookupEnv(k)
		os.Unsetenv(k)
		t.Cleanup(func() {
			if existed {
				os.Setenv(k, prev)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}
