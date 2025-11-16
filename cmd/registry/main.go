package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kolaente/registry/pkg/acl"
	"github.com/kolaente/registry/pkg/auth"
	"github.com/kolaente/registry/pkg/config"
	"github.com/kolaente/registry/pkg/ratelimit"
	"github.com/kolaente/registry/pkg/registry"
	"github.com/urfave/cli/v2"
	"golang.org/x/time/rate"
)

func main() {
	app := &cli.App{
		Name:  "registry",
		Usage: "Self-contained Docker registry with integrated authentication",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "config.yaml",
				Usage:   "Path to configuration file",
				EnvVars: []string{"CONFIG_PATH"},
			},
		},
		Action: runServer,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runServer(c *cli.Context) error {
	configPath := c.String("config")

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	log.Printf("Starting Docker registry server on %s\n", cfg.Server.Addr)

	// Create ACL matcher
	aclMatcher := acl.NewMatcher(cfg.ACL)

	// Create token service
	tokenService, err := auth.NewTokenServiceFromFiles(
		cfg.Auth.Issuer,
		cfg.Auth.Service,
		cfg.Auth.SigningMethod,
		cfg.Auth.PrivateKey,
		cfg.Auth.PublicKey,
		cfg.Auth.HMACSecret,
	)
	if err != nil {
		return fmt.Errorf("failed to create token service: %w", err)
	}

	// Save generated keys if using RSA and paths are specified and files don't exist
	if cfg.Auth.SigningMethod == "rsa" && cfg.Auth.PrivateKey != "" && cfg.Auth.PublicKey != "" {
		if _, err := os.Stat(cfg.Auth.PrivateKey); os.IsNotExist(err) {
			log.Println("Generating and saving RSA key pair...")
			if err := tokenService.SaveKeys(cfg.Auth.PrivateKey, cfg.Auth.PublicKey); err != nil {
				return fmt.Errorf("failed to save keys: %w", err)
			}
			log.Printf("Keys saved to %s and %s\n", cfg.Auth.PrivateKey, cfg.Auth.PublicKey)
		}
	}

	// Create auth handler
	authHandler := auth.NewHandler(tokenService, aclMatcher, cfg.Users, cfg.Auth.Realm, cfg.Auth.Service)

	// Create registry handler
	registryHandler, err := registry.NewHandler(cfg)
	if err != nil {
		return fmt.Errorf("failed to create registry handler: %w", err)
	}

	// Create auth middleware
	authMiddleware := auth.NewAuthMiddleware(tokenService)

	// Create rate limiter if enabled
	var rateLimitMiddleware func(http.Handler) http.Handler
	if cfg.RateLimit.Enabled {
		log.Printf("Rate limiting enabled: %.1f req/sec with burst of %d",
			cfg.RateLimit.RequestsPerSec, cfg.RateLimit.Burst)

		limiter := ratelimit.NewLimiter(
			rate.Limit(cfg.RateLimit.RequestsPerSec),
			cfg.RateLimit.Burst,
			5*time.Minute, // Cleanup old visitors every 5 minutes
		)
		rateLimitMiddleware = limiter.Middleware
	} else {
		log.Println("Rate limiting disabled")
		// No-op middleware
		rateLimitMiddleware = func(next http.Handler) http.Handler {
			return next
		}
	}

	// Set up HTTP router
	mux := http.NewServeMux()

	// Token endpoint (with rate limiting)
	mux.Handle("/v2/token", rateLimitMiddleware(authHandler))

	// Registry endpoints (with auth and rate limiting)
	mux.Handle("/v2/", rateLimitMiddleware(authMiddleware.Middleware(registryHandler)))

	// Health check endpoint (no rate limiting)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Start server
	server := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: mux,
	}

	if cfg.Server.TLS.Enabled {
		log.Printf("Starting HTTPS server on %s\n", cfg.Server.Addr)
		return server.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	}

	log.Printf("Starting HTTP server on %s\n", cfg.Server.Addr)
	return server.ListenAndServe()
}
