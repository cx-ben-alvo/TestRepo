package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultsDoNotUsePlainHTTPPort verifies that the default server port
// is not a plain-HTTP port (:80 or :8080).  The server must always be started
// on a TLS port so that the absence of an explicit TLS_CERT_FILE / TLS_KEY_FILE
// causes a fast-fail before any listener is opened (see main.go).
func TestLoad_DefaultsDoNotUsePlainHTTPPort(t *testing.T) {
	// Ensure relevant env vars are not set.
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	plainHTTPPorts := map[string]bool{":80": true, ":8080": true, "80": true, "8080": true}
	if plainHTTPPorts[cfg.ServerPort] {
		t.Errorf("default ServerPort %q is a plain-HTTP port; server must default to a TLS port", cfg.ServerPort)
	}
}

// TestLoad_TLSFieldsDefaultToEmpty verifies that TLSCertFile and TLSKeyFile
// default to empty strings when the corresponding env vars are unset.
// A non-empty default would silently succeed even when no certificates are
// deployed, which is a misconfiguration risk.
func TestLoad_TLSFieldsDefaultToEmpty(t *testing.T) {
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

// TestLoad_TLSEnvVarsAreRespected verifies that TLSCertFile and TLSKeyFile
// are populated from the TLS_CERT_FILE and TLS_KEY_FILE environment variables.
func TestLoad_TLSEnvVarsAreRespected(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.crt"
	const wantKey = "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	t.Cleanup(func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	})

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: want %q, got %q", wantCert, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: want %q, got %q", wantKey, cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortEnvVar verifies that SERVER_PORT overrides the default.
func TestLoad_ServerPortEnvVar(t *testing.T) {
	const wantPort = ":9443"

	os.Setenv("SERVER_PORT", wantPort)
	t.Cleanup(func() { os.Unsetenv("SERVER_PORT") })

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort: want %q, got %q", wantPort, cfg.ServerPort)
	}
}

// TestLoad_AllTLSFieldsPresent is a structural check that the Config struct
// exposes both TLS fields.  This guards against accidental removal of the
// TLS-related fields from the struct during future refactoring.
func TestLoad_AllTLSFieldsPresent(t *testing.T) {
	cfg := Load()

	// The zero value is fine here — we are only checking that the fields exist
	// at compile time.  The assertion is intentionally trivial.
	_ = cfg.TLSCertFile
	_ = cfg.TLSKeyFile
}

// TestRequireTLSConfig_BothMissing documents that a Config with empty TLS
// fields should be rejected before a listener is opened.  The enforcement
// lives in main(), so this test validates the condition that main() checks.
func TestRequireTLSConfig_BothMissing(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		t.Skip("env vars are set; skipping missing-TLS-config test")
	}

	// Simulate the guard that main() enforces: both fields must be non-empty.
	tlsConfigured := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if tlsConfigured {
		t.Error("expected TLS to NOT be configured when env vars are absent")
	}
}

// TestRequireTLSConfig_OnlyOneMissing documents that partial TLS configuration
// (cert provided but no key, or key provided but no cert) also fails the guard.
func TestRequireTLSConfig_OnlyOneMissing(t *testing.T) {
	cases := []struct {
		name     string
		certFile string
		keyFile  string
	}{
		{"cert set, key missing", "/etc/ssl/certs/server.crt", ""},
		{"cert missing, key set", "", "/etc/ssl/private/server.key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("TLS_CERT_FILE", tc.certFile)
			os.Setenv("TLS_KEY_FILE", tc.keyFile)
			t.Cleanup(func() {
				os.Unsetenv("TLS_CERT_FILE")
				os.Unsetenv("TLS_KEY_FILE")
			})

			cfg := Load()

			// The guard in main() requires BOTH to be non-empty.
			tlsConfigured := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
			if tlsConfigured {
				t.Errorf("expected TLS to NOT be fully configured for case %q", tc.name)
			}
		})
	}
}
