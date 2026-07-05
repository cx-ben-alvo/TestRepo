package config

import (
	"os"
	"testing"
)

// TestTLSEnabled verifies that TLSEnabled returns true only when both cert
// and key file paths are non-empty (CWE-319 regression guard).
func TestTLSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		want     bool
	}{
		{
			name:     "both cert and key set – TLS enabled",
			certFile: "/etc/tls/server.crt",
			keyFile:  "/etc/tls/server.key",
			want:     true,
		},
		{
			name:     "only cert set – TLS disabled",
			certFile: "/etc/tls/server.crt",
			keyFile:  "",
			want:     false,
		},
		{
			name:     "only key set – TLS disabled",
			certFile: "",
			keyFile:  "/etc/tls/server.key",
			want:     false,
		},
		{
			name:     "neither cert nor key – TLS disabled",
			certFile: "",
			keyFile:  "",
			want:     false,
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
				t.Errorf("TLSEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLoadDefaultsHaveNoTLS verifies that the default configuration does NOT
// silently enable a plaintext listener by confirming TLS fields default to
// empty (operators must explicitly supply TLS paths).
func TestLoadDefaultsHaveNoTLS(t *testing.T) {
	// Ensure environment variables are cleared so we test pure defaults.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty TLSCertFile by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty TLSKeyFile by default, got %q", cfg.TLSKeyFile)
	}
	// TLSEnabled must report false when defaults are used.
	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() should return false when no TLS paths are configured")
	}
}

// TestLoadTLSFromEnvironment verifies that TLS configuration is picked up from
// the TLS_CERT_FILE and TLS_KEY_FILE environment variables and that
// TLSEnabled() correctly reflects the loaded values.
func TestLoadTLSFromEnvironment(t *testing.T) {
	const certPath = "/run/secrets/tls.crt"
	const keyPath = "/run/secrets/tls.key"

	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("TLSCertFile = %q, want %q", cfg.TLSCertFile, certPath)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("TLSKeyFile = %q, want %q", cfg.TLSKeyFile, keyPath)
	}
	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled() should return true when both TLS paths are configured")
	}
}

// TestLoadTLSPartialEnvironment verifies that providing only one of the two TLS
// environment variables is not sufficient to enable TLS (both are required).
func TestLoadTLSPartialEnvironment(t *testing.T) {
	t.Run("only cert env var set", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "/run/secrets/tls.crt")
		os.Unsetenv("TLS_KEY_FILE")

		cfg := Load()
		if cfg.TLSEnabled() {
			t.Error("TLSEnabled() should return false when only cert is set")
		}
	})

	t.Run("only key env var set", func(t *testing.T) {
		os.Unsetenv("TLS_CERT_FILE")
		t.Setenv("TLS_KEY_FILE", "/run/secrets/tls.key")

		cfg := Load()
		if cfg.TLSEnabled() {
			t.Error("TLSEnabled() should return false when only key is set")
		}
	})
}
