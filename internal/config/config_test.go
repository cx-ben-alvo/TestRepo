package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultTLSFields verifies that the default configuration includes
// TLS certificate and key file paths so the server always starts in TLS mode.
func TestLoad_DefaultTLSFields(t *testing.T) {
	// Clear any env overrides that might exist in the test environment.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile == "" {
		t.Error("TLSCertFile must have a non-empty default value; an empty path causes ListenAndServeTLS to fail at startup")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("TLSKeyFile must have a non-empty default value; an empty path causes ListenAndServeTLS to fail at startup")
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLS_CERT_FILE and TLS_KEY_FILE
// environment variables are respected, allowing operators to supply
// production certificates at deploy time without code changes.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	const certPath = "/etc/ssl/certs/server.pem"
	const keyPath = "/etc/ssl/private/server.key"

	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("TLSCertFile: expected %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("TLSKeyFile: expected %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoad_DefaultServerPort ensures the default port is still populated after
// adding TLS fields (regression guard).
func TestLoad_DefaultServerPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("ServerPort must have a non-empty default value")
	}
}

// TestLoad_AllFieldsPresent is a structural test that confirms all required
// configuration fields (including the two new TLS fields) are populated by
// Load() when no environment variables override them.
func TestLoad_AllFieldsPresent(t *testing.T) {
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	fields := map[string]string{
		"ServerPort":  cfg.ServerPort,
		"CloneDir":    cfg.CloneDir,
		"DownloadDir": cfg.DownloadDir,
		"TLSCertFile": cfg.TLSCertFile,
		"TLSKeyFile":  cfg.TLSKeyFile,
	}

	for name, value := range fields {
		if value == "" {
			t.Errorf("Config.%s must not be empty by default", name)
		}
	}
}
