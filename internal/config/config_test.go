package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that Load() returns expected defaults when
// no environment variables are set.
func TestLoad_DefaultValues(t *testing.T) {
	// Ensure the relevant env vars are unset for this test
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Default port should now be the TLS port, not plain-text :8081
	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort :8443, got %s", cfg.ServerPort)
	}

	// TLS fields must default to empty strings — absence signals that TLS is
	// not yet configured and the server must refuse to start (CWE-319 guard).
	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty TLSCertFile by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty TLSKeyFile by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS_CERT_FILE and TLS_KEY_FILE are read
// from the environment and stored in the Config struct.
func TestLoad_TLSEnvVars(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/certs/server.crt" {
		t.Errorf("expected TLSCertFile /etc/ssl/certs/server.crt, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/private/server.key" {
		t.Errorf("expected TLSKeyFile /etc/ssl/private/server.key, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortOverride verifies that SERVER_PORT env var overrides the
// default TLS port.
func TestLoad_ServerPortOverride(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort :9443, got %s", cfg.ServerPort)
	}
}

// TestLoad_TLSFieldsPresent ensures the Config struct exposes TLSCertFile and
// TLSKeyFile fields — these are required for CWE-319 remediation so the
// server can call http.ListenAndServeTLS.
func TestLoad_TLSFieldsPresent(t *testing.T) {
	cfg := Load()

	// Compile-time check: if Config no longer has these fields the test won't
	// compile, which is the desired regression signal.
	_ = cfg.TLSCertFile
	_ = cfg.TLSKeyFile
}

// TestLoad_AllEnvVars verifies all environment variables are honoured together.
func TestLoad_AllEnvVars(t *testing.T) {
	os.Setenv("SERVER_PORT", ":8443")
	os.Setenv("CLONE_DIR", "/tmp/clones")
	os.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	os.Setenv("TLS_CERT_FILE", "/tmp/cert.pem")
	os.Setenv("TLS_KEY_FILE", "/tmp/key.pem")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("CLONE_DIR")
		os.Unsetenv("DOWNLOAD_DIR")
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.ServerPort != ":8443" {
		t.Errorf("ServerPort: got %q, want :8443", cfg.ServerPort)
	}
	if cfg.CloneDir != "/tmp/clones" {
		t.Errorf("CloneDir: got %q, want /tmp/clones", cfg.CloneDir)
	}
	if cfg.DownloadDir != "/tmp/downloads" {
		t.Errorf("DownloadDir: got %q, want /tmp/downloads", cfg.DownloadDir)
	}
	if cfg.TLSCertFile != "/tmp/cert.pem" {
		t.Errorf("TLSCertFile: got %q, want /tmp/cert.pem", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/tmp/key.pem" {
		t.Errorf("TLSKeyFile: got %q, want /tmp/key.pem", cfg.TLSKeyFile)
	}
}

// TestLoad_PlainHTTPPortNotDefault ensures the default port is no longer the
// legacy plain-text :8081, which would indicate a regression to CWE-319.
func TestLoad_PlainHTTPPortNotDefault(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort == ":8081" {
		t.Error("default ServerPort must not be :8081 (plain-text HTTP); " +
			"server requires TLS — use :8443 or set SERVER_PORT to a TLS port")
	}
}
