package config

import "os"

// Config holds application configuration
type Config struct {
	ServerPort  string
	CloneDir    string
	DownloadDir string
	// TLSCertFile and TLSKeyFile are paths to the TLS certificate and private key.
	// When both are set, the server uses HTTPS (TLS); otherwise it refuses to start.
	TLSCertFile string
	TLSKeyFile  string
}

// Load loads configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", ":8443"),
		CloneDir:    getEnv("CLONE_DIR", "/tmp/clones"),
		DownloadDir: getEnv("DOWNLOAD_DIR", "/tmp/downloads"),
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
