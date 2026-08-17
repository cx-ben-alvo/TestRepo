package main

import (
	"fmt"
	"log"
	http20 "net/http"
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

	// Register routes — wrapped with SecurityHeaders middleware so that every
	// response carries a Content-Security-Policy and related defence headers.
	http20.HandleFunc("/api/repo/create", handler.SecurityHeaders(h.CreateRepo))
	http20.HandleFunc("/api/repo/clone", handler.SecurityHeaders(h.CloneRepo))
	http20.HandleFunc("/api/repo/list", handler.SecurityHeaders(h.ListRepos))

	// Start server
	fmt.Printf("Server starting on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	// Use TLS (HTTPS) to protect data in transit and prevent MITM attacks.
	// TLS_CERT_FILE and TLS_KEY_FILE must point to a valid certificate and
	// private key (e.g. generated via Let's Encrypt or a corporate PKI).
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE environment variables must be set; plain-text HTTP is not permitted")
	}
	log.Fatal(http20.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
