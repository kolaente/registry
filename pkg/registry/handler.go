package registry

import (
	"context"
	"net/http"

	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry/handlers"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/s3-aws"
	"github.com/kolaente/registry/pkg/config"
)

// Handler wraps the distribution registry handler
type Handler struct {
	app *handlers.App
}

// NewHandler creates a new registry handler
func NewHandler(cfg *config.Config) (*Handler, error) {
	// Create distribution configuration
	// Note: We don't configure Auth here because we handle authentication
	// ourselves through middleware. Distribution will run without auth,
	// and our middleware will protect the endpoints.
	// We also don't set HTTP.Addr since we're wrapping the registry in our own HTTP server.

	// Configure storage based on config
	var storage configuration.Storage
	if cfg.Storage.S3.Bucket != "" {
		// Use S3 storage
		s3Params := configuration.Parameters{
			"region":         cfg.Storage.S3.Region,
			"bucket":         cfg.Storage.S3.Bucket,
			"rootdirectory":  cfg.Storage.S3.RootDirectory,
			"encrypt":        cfg.Storage.S3.Encrypt,
			"secure":         cfg.Storage.S3.Secure,
		}
		// Only include credentials if provided (allows IAM role authentication)
		if cfg.Storage.S3.AccessKey != "" {
			s3Params["accesskey"] = cfg.Storage.S3.AccessKey
		}
		if cfg.Storage.S3.SecretKey != "" {
			s3Params["secretkey"] = cfg.Storage.S3.SecretKey
		}
		// Only include regionendpoint if provided (for S3-compatible services)
		if cfg.Storage.S3.RegionEndpoint != "" {
			s3Params["regionendpoint"] = cfg.Storage.S3.RegionEndpoint
		}

		storage = configuration.Storage{
			"s3": s3Params,
			"delete": configuration.Parameters{
				"enabled": true,
			},
		}
	} else {
		// Use filesystem storage
		storage = configuration.Storage{
			"filesystem": configuration.Parameters{
				"rootdirectory": cfg.Storage.Filesystem.RootDirectory,
			},
			"delete": configuration.Parameters{
				"enabled": true,
			},
		}
	}

	distConfig := &configuration.Configuration{
		Version: "0.1",
		Storage: storage,
		HTTP: configuration.HTTP{
			Headers: http.Header{
				"X-Content-Type-Options": []string{"nosniff"},
			},
		},
	}

	// Set log level
	distConfig.Log.Level = "info"
	distConfig.Log.Formatter = "text"

	// Create registry app
	app := handlers.NewApp(context.Background(), distConfig)

	return &Handler{
		app: app,
	}, nil
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.app.ServeHTTP(w, r)
}
