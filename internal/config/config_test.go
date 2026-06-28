package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultsUseTLS verifies that the default configuration uses HTTPS port 8443
// instead of the old plain-text HTTP port 8081 (CWE-319 regression guard).
func TestLoad_DefaultsUseTLS(t *testing.T) {
	// Ensure env vars that might be set by the environment don't interfere.
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort :8443 (TLS), got %s", cfg.ServerPort)
	}
}

// TestLoad_TLSFieldsExist verifies the Config struct exposes TLSCertFile and TLSKeyFile.
func TestLoad_TLSFieldsExist(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Both must default to empty string when env vars are absent, signalling that
	// the server should reject startup until real certificate paths are supplied.
	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty TLSCertFile by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty TLSKeyFile by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFromEnv verifies that TLS cert/key paths are picked up from environment variables.
func TestLoad_TLSFromEnv(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.crt"
	const wantKey = "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer os.Unsetenv("TLS_CERT_FILE")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: expected %q, got %q", wantCert, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: expected %q, got %q", wantKey, cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortFromEnv verifies the SERVER_PORT env var is respected.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	const wantPort = ":9443"
	os.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort: expected %q, got %q", wantPort, cfg.ServerPort)
	}
}

// TestLoad_CloneDirFromEnv verifies the CLONE_DIR env var is respected.
func TestLoad_CloneDirFromEnv(t *testing.T) {
	const wantDir = "/tmp/clones"
	os.Setenv("CLONE_DIR", wantDir)
	defer os.Unsetenv("CLONE_DIR")

	cfg := Load()

	if cfg.CloneDir != wantDir {
		t.Errorf("CloneDir: expected %q, got %q", wantDir, cfg.CloneDir)
	}
}

// TestLoad_DownloadDirFromEnv verifies the DOWNLOAD_DIR env var is respected.
func TestLoad_DownloadDirFromEnv(t *testing.T) {
	const wantDir = "/tmp/downloads"
	os.Setenv("DOWNLOAD_DIR", wantDir)
	defer os.Unsetenv("DOWNLOAD_DIR")

	cfg := Load()

	if cfg.DownloadDir != wantDir {
		t.Errorf("DownloadDir: expected %q, got %q", wantDir, cfg.DownloadDir)
	}
}

// TestTLSEnforcement_BothFieldsRequired documents that the server MUST fail to start when
// TLS cert/key are absent. This test validates the config invariant: both must be non-empty
// for the server to be safely started with ListenAndServeTLS.
func TestTLSEnforcement_BothFieldsRequired(t *testing.T) {
	tests := []struct {
		name        string
		certEnv     string
		keyEnv      string
		expectReady bool
	}{
		{
			name:        "both empty — server must not start (plaintext would be used)",
			certEnv:     "",
			keyEnv:      "",
			expectReady: false,
		},
		{
			name:        "cert only — incomplete TLS config, server must not start",
			certEnv:     "/path/to/cert.crt",
			keyEnv:      "",
			expectReady: false,
		},
		{
			name:        "key only — incomplete TLS config, server must not start",
			certEnv:     "",
			keyEnv:      "/path/to/key.key",
			expectReady: false,
		},
		{
			name:        "both provided — TLS config is complete, server may start",
			certEnv:     "/path/to/cert.crt",
			keyEnv:      "/path/to/key.key",
			expectReady: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.certEnv != "" {
				os.Setenv("TLS_CERT_FILE", tc.certEnv)
				defer os.Unsetenv("TLS_CERT_FILE")
			} else {
				os.Unsetenv("TLS_CERT_FILE")
			}
			if tc.keyEnv != "" {
				os.Setenv("TLS_KEY_FILE", tc.keyEnv)
				defer os.Unsetenv("TLS_KEY_FILE")
			} else {
				os.Unsetenv("TLS_KEY_FILE")
			}

			cfg := Load()
			ready := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""

			if ready != tc.expectReady {
				t.Errorf("TLS readiness mismatch: expected ready=%v, got ready=%v (cert=%q, key=%q)",
					tc.expectReady, ready, cfg.TLSCertFile, cfg.TLSKeyFile)
			}
		})
	}
}
