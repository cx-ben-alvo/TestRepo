package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies the default configuration values are set correctly,
// including the TLS fields defaulting to empty (TLS not configured).
func TestLoad_Defaults(t *testing.T) {
	// Ensure no relevant env vars are set during this test
	for _, key := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
		os.Unsetenv(key)
	}

	cfg := Load()

	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort ':8443', got %q", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("expected default TLSCertFile to be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected default TLSKeyFile to be empty, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS configuration is read from environment variables.
func TestLoad_TLSEnvVars(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/certs/server.crt" {
		t.Errorf("expected TLSCertFile '/etc/ssl/certs/server.crt', got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/private/server.key" {
		t.Errorf("expected TLSKeyFile '/etc/ssl/private/server.key', got %q", cfg.TLSKeyFile)
	}
}

// TestTLSEnabled_BothPaths verifies TLSEnabled returns true only when both cert
// and key file paths are non-empty.
func TestTLSEnabled_BothPaths(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		want     bool
	}{
		{
			name:     "both empty — TLS disabled (prevents plain-text startup)",
			certFile: "",
			keyFile:  "",
			want:     false,
		},
		{
			name:     "cert only — TLS disabled",
			certFile: "/etc/ssl/server.crt",
			keyFile:  "",
			want:     false,
		},
		{
			name:     "key only — TLS disabled",
			certFile: "",
			keyFile:  "/etc/ssl/server.key",
			want:     false,
		},
		{
			name:     "both set — TLS enabled",
			certFile: "/etc/ssl/server.crt",
			keyFile:  "/etc/ssl/server.key",
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}
			got := cfg.TLSEnabled()
			if got != tc.want {
				t.Errorf("TLSEnabled() = %v, want %v (certFile=%q, keyFile=%q)",
					got, tc.want, tc.certFile, tc.keyFile)
			}
		})
	}
}

// TestTLSEnabled_DefaultConfigIsFalse verifies that a freshly loaded default
// Config (no env vars set) has TLS disabled, ensuring the server will refuse
// to start without explicit TLS configuration — preventing CWE-319.
func TestTLSEnabled_DefaultConfigIsFalse(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() should return false when TLS_CERT_FILE and TLS_KEY_FILE are not set; " +
			"the server must not start in plain-text mode (CWE-319)")
	}
}

// TestLoad_ServerPortEnvVar verifies the server port can be overridden via env var.
func TestLoad_ServerPortEnvVar(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort ':9443', got %q", cfg.ServerPort)
	}
}

// TestLoad_DefaultServerPortIsHTTPS verifies the default port uses the conventional
// HTTPS port (8443) and not a plain-HTTP port, reinforcing TLS-by-default posture.
func TestLoad_DefaultServerPortIsHTTPS(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	// Port :8080 is the canonical plain-HTTP port; the default must not be it.
	if cfg.ServerPort == ":8080" || cfg.ServerPort == ":8081" {
		t.Errorf("default ServerPort must not be a plain-HTTP port, got %q; use an HTTPS port like :8443", cfg.ServerPort)
	}
}
