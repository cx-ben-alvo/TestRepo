package config

import "testing"

func TestLoadTLSDefaults(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")

	cfg := Load()
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		t.Fatalf("expected non-empty default TLS paths, got cert=%q key=%q", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}

func TestLoadTLSFromEnv(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/tls/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/tls/tls.key")

	cfg := Load()
	if cfg.TLSCertFile != "/etc/tls/tls.crt" {
		t.Errorf("unexpected cert path %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/tls/tls.key" {
		t.Errorf("unexpected key path %q", cfg.TLSKeyFile)
	}
}
