package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that config defaults are applied when
// environment variables are not set.
func TestLoad_Defaults(t *testing.T) {
	// Clear TLS env vars to ensure defaults are used
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort ':8081', got %q", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty TLSCertFile by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty TLSKeyFile by default, got %q", cfg.TLSKeyFile)
	}
}

// TestTLSEnabled_FalseWhenNotConfigured verifies that TLSEnabled returns false
// when neither TLS_CERT_FILE nor TLS_KEY_FILE is set. This tests the security
// baseline: the operator must explicitly opt in to TLS.
func TestTLSEnabled_FalseWhenNotConfigured(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() should return false when TLS_CERT_FILE and TLS_KEY_FILE are not set")
	}
}

// TestTLSEnabled_FalseWhenOnlyCertSet verifies that TLSEnabled requires BOTH
// TLS_CERT_FILE and TLS_KEY_FILE to be set; a partial configuration must not
// enable TLS silently.
func TestTLSEnabled_FalseWhenOnlyCertSet(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/path/to/cert.pem")
	os.Unsetenv("TLS_KEY_FILE")
	defer os.Unsetenv("TLS_CERT_FILE")

	cfg := Load()

	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() should return false when only TLS_CERT_FILE is set (TLS_KEY_FILE missing)")
	}
}

// TestTLSEnabled_FalseWhenOnlyKeySet mirrors the partial-config check for the key side.
func TestTLSEnabled_FalseWhenOnlyKeySet(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Setenv("TLS_KEY_FILE", "/path/to/key.pem")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() should return false when only TLS_KEY_FILE is set (TLS_CERT_FILE missing)")
	}
}

// TestTLSEnabled_TrueWhenBothSet verifies that TLSEnabled returns true and the
// correct paths are populated when both TLS environment variables are provided.
// This is the critical security path: when TLS is configured, the server MUST
// use ListenAndServeTLS instead of the plain-text ListenAndServe.
func TestTLSEnabled_TrueWhenBothSet(t *testing.T) {
	certPath := "/etc/ssl/certs/server.crt"
	keyPath := "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", certPath)
	os.Setenv("TLS_KEY_FILE", keyPath)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled() should return true when both TLS_CERT_FILE and TLS_KEY_FILE are set")
	}
	if cfg.TLSCertFile != certPath {
		t.Errorf("TLSCertFile: expected %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("TLSKeyFile: expected %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestTLSEnabled_DirectStruct tests TLSEnabled() directly on Config structs
// without environment variable involvement, covering all combinations.
func TestTLSEnabled_DirectStruct(t *testing.T) {
	cases := []struct {
		name     string
		certFile string
		keyFile  string
		want     bool
	}{
		{
			name:     "both empty – TLS disabled",
			certFile: "",
			keyFile:  "",
			want:     false,
		},
		{
			name:     "only cert – TLS disabled",
			certFile: "cert.pem",
			keyFile:  "",
			want:     false,
		},
		{
			name:     "only key – TLS disabled",
			certFile: "",
			keyFile:  "key.pem",
			want:     false,
		},
		{
			name:     "both set – TLS enabled",
			certFile: "cert.pem",
			keyFile:  "key.pem",
			want:     true,
		},
	}

	for _, tc := range cases {
		tc := tc
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

// TestLoad_EnvOverride verifies that environment variables override defaults for
// all Config fields including the new TLS fields.
func TestLoad_EnvOverride(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	os.Setenv("TLS_CERT_FILE", "/run/secrets/tls.crt")
	os.Setenv("TLS_KEY_FILE", "/run/secrets/tls.key")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("ServerPort: expected ':9443', got %q", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "/run/secrets/tls.crt" {
		t.Errorf("TLSCertFile: expected '/run/secrets/tls.crt', got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/run/secrets/tls.key" {
		t.Errorf("TLSKeyFile: expected '/run/secrets/tls.key', got %q", cfg.TLSKeyFile)
	}
	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled() should be true when both TLS paths are overridden via env")
	}
}
