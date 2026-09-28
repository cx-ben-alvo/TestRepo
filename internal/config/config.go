package config

import "os"

// Config holds application configuration
type Config struct {
	ServerPort  string
	CloneDir    string
	DownloadDir string
	// TLS configuration for secure HTTPS transport
	TLSCertFile string
	TLSKeyFile  string
}

// Load loads configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", ":8081"),
		CloneDir:    getEnv("CLONE_DIR", "/Users/benalvo/clones"),
		DownloadDir: getEnv("DOWNLOAD_DIR", "/Users/benalvo/downloads"),
		// TLS certificate and key paths must be set via environment variables
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),
	}
}

// TLSEnabled reports whether TLS is fully configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
