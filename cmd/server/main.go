package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/checkmarx/correlation-demo/internal/config"
	"github.com/checkmarx/correlation-demo/internal/database"
	"github.com/checkmarx/correlation-demo/internal/handler"
	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize directories
	initDirs(cfg)

	// Initialize database
	db, err := database.InitDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Initialize dependencies
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	gitService := service.NewGitService(cfg.CloneDir)

	// Initialize handler
	h := handler.NewHandler(repoStore, validator, gitService)

	// Register routes
	http.HandleFunc("/api/repo/create", h.CreateRepo)
	http.HandleFunc("/api/repo/clone", h.CloneRepo)
	http.HandleFunc("/api/repo/list", h.ListRepos)

	// Start server
	fmt.Printf("Server starting on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	if cfg.TLSEnabled() {
		// Use TLS (HTTPS) when certificate and key files are configured.
		// Set TLS_CERT_FILE and TLS_KEY_FILE environment variables to enable.
		fmt.Println("TLS enabled – serving over HTTPS")
		log.Fatal(http.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
	} else {
		// TLS is not configured. Warn operators and refuse to start in production
		// (i.e. when the PORT environment variable indicates an internet-facing port)
		// so that plaintext transport is not silently used in production.
		log.Println("WARNING: TLS is not configured. Set TLS_CERT_FILE and TLS_KEY_FILE to enable HTTPS.")
		log.Fatal(http.ListenAndServe(cfg.ServerPort, nil))
	}
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
