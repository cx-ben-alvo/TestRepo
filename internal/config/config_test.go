package config

import (
	"os"
	"testing"
)

// TestTLSEnabled verifies that TLSEnabled returns true only when both cert and
// key file paths are configured, preventing accidental plain-text HTTP startup.
func TestTLSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		want     bool
	}{
		{
			name:     "both cert and key set - TLS enabled",
			certFile: "/etc/ssl/certs/server.crt",
			keyFile:  "/etc/ssl/private/server.key",
			want:     true,
		},
		{
			name:     "cert missing - TLS disabled",
			certFile: "",
			keyFile:  "/etc/ssl/private/server.key",
			want:     false,
		},
		{
			name:     "key missing - TLS disabled",
			certFile: "/etc/ssl/certs/server.crt",
			keyFile:  "",
			want:     false,
		},
		{
			name:     "both missing - TLS disabled",
			certFile: "",
			keyFile:  "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				TLSCertFile: tt.certFile,
				TLSKeyFile:  tt.keyFile,
			}
			if got := cfg.TLSEnabled(); got != tt.want {
				t.Errorf("TLSEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLoadTLSFromEnv verifies that Load() reads TLS paths from environment
// variables and does not fall back to empty strings when env vars are set.
func TestLoadTLSFromEnv(t *testing.T) {
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
		t.Error("TLSEnabled() = false, want true when both env vars are set")
	}
}

// TestLoadTLSDefaultsEmpty verifies that when TLS env vars are absent, the
// paths default to empty strings so TLSEnabled() returns false and the server
// refuses to start without explicit configuration.
func TestLoadTLSDefaultsEmpty(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile default = %q, want empty string", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile default = %q, want empty string", cfg.TLSKeyFile)
	}
	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true, want false when env vars are unset (server must not start in plain-text mode)")
	}
}

// TestLoadDefaults verifies non-TLS fields still load with expected defaults.
func TestLoadDefaults(t *testing.T) {
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("ServerPort should have a non-empty default")
	}
}
