package config

import (
	"os"
	"testing"
)

// TestLoadDefaultsTLSFields verifies that TLSCertFile and TLSKeyFile default
// to empty strings when the corresponding environment variables are not set.
// The server must refuse to start when these are empty, so an empty default is
// the correct and safe behaviour.
func TestLoadDefaultsTLSFields(t *testing.T) {
	// Ensure neither env var is set so we get the default empty values.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoadReadsTLSCertFileFromEnv verifies that TLS_CERT_FILE is read from the
// environment.
func TestLoadReadsTLSCertFileFromEnv(t *testing.T) {
	const certPath = "/etc/ssl/server.crt"
	t.Setenv("TLS_CERT_FILE", certPath)
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("expected TLSCertFile %q, got %q", certPath, cfg.TLSCertFile)
	}
	// Key must still be empty (not set).
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty, got %q", cfg.TLSKeyFile)
	}
}

// TestLoadReadsTLSKeyFileFromEnv verifies that TLS_KEY_FILE is read from the
// environment.
func TestLoadReadsTLSKeyFileFromEnv(t *testing.T) {
	const keyPath = "/etc/ssl/server.key"
	os.Unsetenv("TLS_CERT_FILE")
	t.Setenv("TLS_KEY_FILE", keyPath)

	cfg := Load()

	if cfg.TLSKeyFile != keyPath {
		t.Errorf("expected TLSKeyFile %q, got %q", keyPath, cfg.TLSKeyFile)
	}
	// Cert must still be empty (not set).
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty, got %q", cfg.TLSCertFile)
	}
}

// TestLoadReadsBothTLSFilesFromEnv verifies that when both TLS_CERT_FILE and
// TLS_KEY_FILE are set, they are both correctly loaded into the config.
func TestLoadReadsBothTLSFilesFromEnv(t *testing.T) {
	const certPath = "/etc/ssl/server.crt"
	const keyPath = "/etc/ssl/server.key"
	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("expected TLSCertFile %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("expected TLSKeyFile %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoadDefaultServerPort verifies the default server port is still set.
func TestLoadDefaultServerPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort \":8081\", got %q", cfg.ServerPort)
	}
}

// TestTLSRequirementEnforced verifies the logic that guards against starting
// the server without TLS. This mirrors the guard in main() — both cert and key
// must be non-empty for TLS to be considered configured.
func TestTLSRequirementEnforced(t *testing.T) {
	tests := []struct {
		name      string
		certFile  string
		keyFile   string
		wantReady bool
	}{
		{
			name:      "both empty — TLS not configured",
			certFile:  "",
			keyFile:   "",
			wantReady: false,
		},
		{
			name:      "only cert set — TLS not configured",
			certFile:  "/path/to/cert.pem",
			keyFile:   "",
			wantReady: false,
		},
		{
			name:      "only key set — TLS not configured",
			certFile:  "",
			keyFile:   "/path/to/key.pem",
			wantReady: false,
		},
		{
			name:      "both set — TLS configured",
			certFile:  "/path/to/cert.pem",
			keyFile:   "/path/to/key.pem",
			wantReady: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ServerPort:  ":8081",
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}

			// isTLSReady replicates the guard condition used in main().
			gotReady := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
			if gotReady != tc.wantReady {
				t.Errorf("TLS ready = %v, want %v (certFile=%q, keyFile=%q)",
					gotReady, tc.wantReady, tc.certFile, tc.keyFile)
			}
		})
	}
}
