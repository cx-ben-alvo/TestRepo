package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that Load() returns sensible defaults when
// no environment variables are set.  The TLS fields must default to empty
// strings so the server startup guard (which calls log.Fatal when they are
// empty) is triggered correctly.
func TestLoad_DefaultValues(t *testing.T) {
	// Make sure environment variables are not set for this test
	unsetEnvVars(t, "SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE")

	cfg := Load()

	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort :8443, got %q", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("expected default TLSCertFile to be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected default TLSKeyFile to be empty, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS_CERT_FILE and TLS_KEY_FILE environment
// variables are correctly read into the Config struct.  This is the primary
// security control that ensures TLS paths are supplied externally rather than
// hardcoded.
func TestLoad_TLSEnvVars(t *testing.T) {
	unsetEnvVars(t, "TLS_CERT_FILE", "TLS_KEY_FILE")

	t.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/certs/server.crt" {
		t.Errorf("expected TLSCertFile /etc/ssl/certs/server.crt, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/private/server.key" {
		t.Errorf("expected TLSKeyFile /etc/ssl/private/server.key, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortEnvVar verifies that SERVER_PORT is read from the
// environment variable.
func TestLoad_ServerPortEnvVar(t *testing.T) {
	unsetEnvVars(t, "SERVER_PORT")
	t.Setenv("SERVER_PORT", ":9443")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort :9443, got %q", cfg.ServerPort)
	}
}

// TestLoad_AllEnvVars verifies that all configuration values are read from
// environment variables when present.
func TestLoad_AllEnvVars(t *testing.T) {
	unsetEnvVars(t, "SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE")

	t.Setenv("SERVER_PORT", ":8444")
	t.Setenv("CLONE_DIR", "/data/clones")
	t.Setenv("DOWNLOAD_DIR", "/data/downloads")
	t.Setenv("TLS_CERT_FILE", "/certs/server.crt")
	t.Setenv("TLS_KEY_FILE", "/certs/server.key")

	cfg := Load()

	if cfg.ServerPort != ":8444" {
		t.Errorf("expected ServerPort :8444, got %q", cfg.ServerPort)
	}
	if cfg.CloneDir != "/data/clones" {
		t.Errorf("expected CloneDir /data/clones, got %q", cfg.CloneDir)
	}
	if cfg.DownloadDir != "/data/downloads" {
		t.Errorf("expected DownloadDir /data/downloads, got %q", cfg.DownloadDir)
	}
	if cfg.TLSCertFile != "/certs/server.crt" {
		t.Errorf("expected TLSCertFile /certs/server.crt, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/certs/server.key" {
		t.Errorf("expected TLSKeyFile /certs/server.key, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsPresent ensures the Config struct exposes TLSCertFile and
// TLSKeyFile fields.  This is a structural guard that will fail to compile if
// the fields are ever removed, preventing accidental regression to plain-text
// transport.
func TestLoad_TLSFieldsPresent(t *testing.T) {
	cfg := &Config{}
	// Verify field assignment compiles and works
	cfg.TLSCertFile = "test.crt"
	cfg.TLSKeyFile = "test.key"

	if cfg.TLSCertFile != "test.crt" {
		t.Errorf("TLSCertFile field not working, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "test.key" {
		t.Errorf("TLSKeyFile field not working, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSMissingCertFile verifies that when only the cert is missing the
// TLSCertFile value is an empty string (the server startup guard will reject
// this configuration).
func TestLoad_TLSMissingCertFile(t *testing.T) {
	unsetEnvVars(t, "TLS_CERT_FILE", "TLS_KEY_FILE")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty TLSCertFile when env var not set, got %q", cfg.TLSCertFile)
	}
}

// TestLoad_TLSMissingKeyFile verifies that when only the key is missing the
// TLSKeyFile value is an empty string (the server startup guard will reject
// this configuration).
func TestLoad_TLSMissingKeyFile(t *testing.T) {
	unsetEnvVars(t, "TLS_CERT_FILE", "TLS_KEY_FILE")
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")

	cfg := Load()

	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty TLSKeyFile when env var not set, got %q", cfg.TLSKeyFile)
	}
}

// unsetEnvVars removes the given environment variables and restores their
// original values (including the unset state) after the test completes.
func unsetEnvVars(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		original, wasSet := os.LookupEnv(key)
		if wasSet {
			t.Cleanup(func() { os.Setenv(key, original) })
		} else {
			t.Cleanup(func() { os.Unsetenv(key) })
		}
		os.Unsetenv(key)
	}
}
