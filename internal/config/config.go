package config

import "os"

// Config holds application configuration
type Config struct {
	ServerPort  string
	CloneDir    string
	DownloadDir string
	// TLSCertFile is the path to the TLS certificate file (PEM format).
	// Required for HTTPS. Set via TLS_CERT_FILE environment variable.
	TLSCertFile string
	// TLSKeyFile is the path to the TLS private key file (PEM format).
	// Required for HTTPS. Set via TLS_KEY_FILE environment variable.
	TLSKeyFile string
}

// Load loads configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", ":8081"),
		CloneDir:    getEnv("CLONE_DIR", "/Users/benalvo/clones"),
		DownloadDir: getEnv("DOWNLOAD_DIR", "/Users/benalvo/downloads"),
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),
	}
}

// TLSEnabled returns true when both TLS certificate and key paths are configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
