package config

import (
	"os"
	"testing"
)

// TestLoad_TLSFieldsPresent verifies that the Config struct exposes TLS
// certificate and key path fields, which are required by the TLS-only server.
func TestLoad_TLSFieldsPresent(t *testing.T) {
	// Ensure env vars are cleared so we get defaults.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// The fields must exist and default to empty string (i.e., TLS is not
	// pre-configured by default; the operator must supply the paths explicitly).
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile default to be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile default to be empty, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLS_CERT_FILE and TLS_KEY_FILE
// environment variables are correctly read into the Config struct.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	wantCert := "/etc/ssl/certs/server.crt"
	wantKey := "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: got %q, want %q", cfg.TLSCertFile, wantCert)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: got %q, want %q", cfg.TLSKeyFile, wantKey)
	}
}

// TestLoad_DefaultPort verifies the server default port changed to 8443
// (the conventional HTTPS port) to reflect that the server now requires TLS.
func TestLoad_DefaultPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	// The default must be an HTTPS-appropriate port, not plain 8081.
	if cfg.ServerPort == ":8081" {
		t.Errorf("default ServerPort is still :8081; expected an HTTPS port (e.g. :8443)")
	}
	if cfg.ServerPort != ":8443" {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, ":8443")
	}
}

// TestLoad_DefaultPortOverrideFromEnv verifies SERVER_PORT env var is respected.
func TestLoad_DefaultPortOverrideFromEnv(t *testing.T) {
	want := ":9443"
	os.Setenv("SERVER_PORT", want)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != want {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, want)
	}
}

// TestLoad_TLSFieldsMissingMeansNoPlainHTTP documents the security invariant:
// when both TLS fields are empty the operator has not provided certificates,
// and the server must refuse to start with plain HTTP rather than silently
// falling back to an unencrypted listener.
//
// This test validates the *config layer* contract (fields are empty by default).
// The enforcement of the "no plain HTTP" rule is tested at the server layer in
// cmd/server/main_tls_test.go.
func TestLoad_TLSFieldsMissingMeansNoPlainHTTP(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	tlsConfigured := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if tlsConfigured {
		// This path is fine too – it means a real cert was supplied via env.
		return
	}

	// Both fields are empty: the server must NOT start with plain HTTP.
	// We verify here that the config exposes the missing state; the server
	// code is responsible for acting on it.
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		t.Error("expected both TLS fields to be empty when env vars are unset")
	}
}
