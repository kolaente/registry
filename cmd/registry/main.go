package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kolaente/registry/pkg/acl"
	"github.com/kolaente/registry/pkg/auth"
	"github.com/kolaente/registry/pkg/config"
	"github.com/kolaente/registry/pkg/gc"
	"github.com/kolaente/registry/pkg/ratelimit"
	"github.com/kolaente/registry/pkg/registry"
	usagepkg "github.com/kolaente/registry/pkg/usage"
	"github.com/urfave/cli/v3"
	"golang.org/x/time/rate"
)

const defaultUsageTableTagLimit = 6

var (
	Version = "dev"
	Commit  = "unknown"
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
			{
				Name:  "usage",
				Usage: "Report attributed image storage usage",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "config.yaml",
						Usage:   "Path to configuration file",
						Sources: cli.EnvVars("CONFIG_PATH"),
					},
					&cli.StringFlag{
						Name:  "format",
						Value: "table",
						Usage: "Output format: table or json",
					},
				},
				Action: runUsage,
			},
			{
				Name:      "add-user",
				Usage:     "Add a user with a hashed password to the config file",
				ArgsUsage: "<username> [password]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "config.yaml",
						Usage:   "Path to configuration file",
						Sources: cli.EnvVars("CONFIG_PATH"),
					},
				},
				Action: runAddUser,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func runServer(ctx context.Context, cmd *cli.Command) error {
	configPath := cmd.String("config")

	log.Printf("Starting registry build: %s", buildInfoString(Version, Commit))

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

func buildInfoString(version, commit string) string {
	return fmt.Sprintf("version=%s commit=%s", version, commit)
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

func runUsage(ctx context.Context, cmd *cli.Command) error {
	configPath := cmd.String("config")
	outputFormat := cmd.String("format")

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Storage.S3.Bucket != "" {
		return fmt.Errorf("usage report currently supports filesystem storage only")
	}

	report, err := usagepkg.AnalyzeFilesystem(cfg.Storage.Filesystem.RootDirectory)
	if err != nil {
		return err
	}

	switch outputFormat {
	case "table":
		printUsageTable(report)
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return fmt.Errorf("failed to encode usage report: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format %q: use table or json", outputFormat)
	}

	return nil
}

func printUsageTable(report *usagepkg.Report) {
	writeUsageTable(os.Stdout, report, defaultUsageTableTagLimit)
}

func writeUsageTable(output io.Writer, report *usagepkg.Report, tagLimit int) {
	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "REPOSITORY\tATTRIBUTED\tREFERENCED\tEXCLUSIVE\tSHARED\tBLOBS\tTAGS")
	for _, repository := range report.Repositories {
		fmt.Fprintf(
			writer,
			"%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			repository.Repository,
			repository.AttributedSize,
			repository.ReferencedSize,
			repository.ExclusiveSize,
			repository.SharedSize,
			repository.BlobCount,
			summarizeTags(repository.Tags, tagLimit),
		)
	}
	writer.Flush()

	fmt.Fprintf(output, "\nTotal blob storage: %s\n", report.TotalBlobSize)
	fmt.Fprintf(output, "Referenced by current tags: %s\n", report.TotalReferencedSize)
	fmt.Fprintf(output, "Unreferenced: %s\n", report.UnreferencedSize)
}

func summarizeTags(tags []string, limit int) string {
	if len(tags) == 0 {
		return "-"
	}
	if limit <= 0 || len(tags) <= limit {
		return strings.Join(tags, ",")
	}

	return fmt.Sprintf("%s,+%d more", strings.Join(tags[:limit], ","), len(tags)-limit)
}

func runAddUser(ctx context.Context, cmd *cli.Command) error {
	configPath := cmd.String("config")

	// Get username from arguments
	args := cmd.Args()
	if args.Len() < 1 {
		return fmt.Errorf("username is required")
	}
	username := args.Get(0)

	// Get or generate password
	var password string
	var err error
	if args.Len() >= 2 {
		password = args.Get(1)
	} else {
		password, err = config.GeneratePassword()
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
		fmt.Printf("Generated password: %s\n", password)
	}

	// Hash the password
	hashedPassword, err := config.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Add user to config file
	if err := config.AddUser(configPath, username, hashedPassword); err != nil {
		return fmt.Errorf("failed to add user: %w", err)
	}

	fmt.Printf("User %q added successfully\n", username)
	return nil
}
