package config

import "os"

// Config holds application configuration
type Config struct {
	ServerPort  string
	CloneDir    string
	DownloadDir string
	TLSCertFile string // path to PEM certificate (env TLS_CERT_FILE)
	TLSKeyFile  string // path to PEM private key (env TLS_KEY_FILE)
}

// Load loads configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", ":8081"),
		CloneDir:    getEnv("CLONE_DIR", "/Users/benalvo/clones"),
		DownloadDir: getEnv("DOWNLOAD_DIR", "/Users/benalvo/downloads"),
		TLSCertFile: getEnv("TLS_CERT_FILE", "certs/server.crt"),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", "certs/server.key"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
