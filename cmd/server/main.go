package main

import (
	"fmt"
	"log"
	http26 "net/http"
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
	http26.HandleFunc("/api/repo/create", h.CreateRepo)
	http26.HandleFunc("/api/repo/clone", h.CloneRepo)
	http26.HandleFunc("/api/repo/list", h.ListRepos)

	// Start server
	fmt.Printf("Server starting on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	// Use TLS (HTTPS) when certificate and key paths are configured to prevent
	// Man-in-the-Middle attacks (CWE-319). TLS_CERT_FILE and TLS_KEY_FILE
	// environment variables must be set to enable encrypted transport.
	if cfg.TLSEnabled() {
		fmt.Println("TLS enabled: serving over HTTPS")
		log.Fatal(http26.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
	} else {
		log.Fatal(fmt.Errorf("TLS is required: set TLS_CERT_FILE and TLS_KEY_FILE environment variables to enable HTTPS"))
	}
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
