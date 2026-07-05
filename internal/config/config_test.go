package config

import (
	"os"
	"testing"
)

// TestLoadDefaults verifies the default configuration values, including that
// TLS fields default to empty strings (requiring explicit configuration).
func TestLoadDefaults(t *testing.T) {
	// Ensure no environment variables interfere with this test
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort ':8443', got '%s'", cfg.ServerPort)
	}
	// TLS fields must default to empty strings so that main() enforces the
	// requirement for operators to explicitly supply certificate paths.
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to default to empty string, got '%s'", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to default to empty string, got '%s'", cfg.TLSKeyFile)
	}
}

// TestLoadFromEnv verifies that TLS paths and server port are read from
// environment variables, enabling operators to configure HTTPS without
// code changes.
func TestLoadFromEnv(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	os.Setenv("TLS_CERT_FILE", "/etc/ssl/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/ssl/server.key")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort ':9443', got '%s'", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "/etc/ssl/server.crt" {
		t.Errorf("expected TLSCertFile '/etc/ssl/server.crt', got '%s'", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/server.key" {
		t.Errorf("expected TLSKeyFile '/etc/ssl/server.key', got '%s'", cfg.TLSKeyFile)
	}
}

// TestTLSConfigPresentWhenBothFieldsSet verifies that the config correctly
// signals TLS readiness when both cert and key paths are provided.
// This guards against regression where TLS paths might be silently dropped.
func TestTLSConfigPresentWhenBothFieldsSet(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/certs/tls.crt")
	os.Setenv("TLS_KEY_FILE", "/certs/tls.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	// Both fields must be non-empty for the server's TLS guard to pass
	if cfg.TLSCertFile == "" {
		t.Error("TLSCertFile should not be empty when TLS_CERT_FILE is set")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("TLSKeyFile should not be empty when TLS_KEY_FILE is set")
	}
}

// TestTLSRequiredFieldsMissing verifies that the config returns empty TLS
// fields when the environment variables are not set, which causes the server
// to refuse to start without TLS — preventing plain-text HTTP exposure (CWE-319).
func TestTLSRequiredFieldsMissing(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Empty TLS paths mean the server will log.Fatal before binding, which is
	// the intended fail-safe to prevent running without encryption.
	tlsReady := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if tlsReady {
		t.Error("expected TLS to be not ready when env vars are absent; server must not start without TLS config")
	}
}

// TestServerPortDefaultsToHTTPS verifies the default port is a conventional
// HTTPS port (not a plain-HTTP port like 8080/8081), reinforcing the intent
// that the service is HTTPS-only.
func TestServerPortDefaultsToHTTPS(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	// The default port should not be a well-known HTTP port
	plainHTTPPorts := map[string]bool{
		":80":   true,
		":8080": true,
		":8081": true,
	}
	if plainHTTPPorts[cfg.ServerPort] {
		t.Errorf("default ServerPort '%s' is a plain-HTTP port; it should be an HTTPS port to prevent CWE-319", cfg.ServerPort)
	}
}
