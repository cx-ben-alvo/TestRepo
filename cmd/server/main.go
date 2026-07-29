package main

import (
	"fmt"
	"log"
	http9 "net/http"
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

	// Require TLS certificate and key to enforce encrypted transport (CWE-319).
	// Set TLS_CERT_FILE and TLS_KEY_FILE environment variables before starting.
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE must be set; plain-text HTTP is not permitted")
	}

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
	http9.HandleFunc("/api/repo/create", h.CreateRepo)
	http9.HandleFunc("/api/repo/clone", h.CloneRepo)
	http9.HandleFunc("/api/repo/list", h.ListRepos)

	// Start server using TLS to protect data in transit
	fmt.Printf("Server starting (HTTPS) on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	log.Fatal(http9.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
