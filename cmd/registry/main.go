package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kolaente/registry/pkg/acl"
	"github.com/kolaente/registry/pkg/auth"
	"github.com/kolaente/registry/pkg/config"
	"github.com/kolaente/registry/pkg/gc"
	"github.com/kolaente/registry/pkg/ratelimit"
	"github.com/kolaente/registry/pkg/registry"
	"github.com/urfave/cli/v3"
	"golang.org/x/time/rate"
)

func main() {
	cmd := &cli.Command{
		Name:  "registry",
		Usage: "Self-contained Docker registry with integrated authentication",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "config.yaml",
				Usage:   "Path to configuration file",
				Sources: cli.EnvVars("CONFIG_PATH"),
			},
		},
		Action: runServer,
		Commands: []*cli.Command{
			{
				Name:  "gc",
				Usage: "Run garbage collection on the registry storage",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "config.yaml",
						Usage:   "Path to configuration file",
						Sources: cli.EnvVars("CONFIG_PATH"),
					},
					&cli.BoolFlag{
						Name:    "dry-run",
						Aliases: []string{"d"},
						Value:   false,
						Usage:   "Do everything except remove the blobs",
					},
					&cli.BoolFlag{
						Name:    "delete-untagged",
						Aliases: []string{"m"},
						Value:   false,
						Usage:   "Delete manifests that are not currently referenced via tag",
					},
				},
				Action: runGC,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func runServer(ctx context.Context, cmd *cli.Command) error {
	configPath := cmd.String("config")

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
	tokenService, err := auth.NewTokenServiceFromConfig(
		cfg.Auth.Issuer,
		cfg.Auth.Service,
		cfg.Auth.HMACSecret,
	)
	if err != nil {
		return fmt.Errorf("failed to create token service: %w", err)
	}

	// Create auth handler
	authHandler := auth.NewHandler(tokenService, aclMatcher, cfg.Users, cfg.Auth.Realm, cfg.Auth.Service)

	// Create registry handler
	registryHandler, err := registry.NewHandler(cfg)
	if err != nil {
		return fmt.Errorf("failed to create registry handler: %w", err)
	}

	// Create auth middleware
	authMiddleware := auth.NewAuthMiddleware(tokenService, cfg.Auth.Service)

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

	// Start garbage collector if enabled
	var garbageCollector *gc.GarbageCollector
	if cfg.GarbageCollector.Enabled {
		log.Printf("Garbage collection enabled: interval=%s, remove_untagged=%v",
			cfg.GarbageCollector.Interval, cfg.GarbageCollector.RemoveUntagged)

		garbageCollector, err = gc.NewGarbageCollector(cfg)
		if err != nil {
			return fmt.Errorf("failed to create garbage collector: %w", err)
		}
		garbageCollector.Start()
		defer garbageCollector.Stop()
	} else {
		log.Println("Garbage collection disabled")
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

	log.Printf("Starting HTTP server on %s\n", cfg.Server.Addr)
	return server.ListenAndServe()
}

func runGC(ctx context.Context, cmd *cli.Command) error {
	configPath := cmd.String("config")
	dryRun := cmd.Bool("dry-run")
	deleteUntagged := cmd.Bool("delete-untagged")

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Run garbage collection
	return gc.RunOnce(ctx, cfg, deleteUntagged, dryRun)
}
