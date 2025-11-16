package registry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry/handlers"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	"github.com/kolaente/registry/pkg/config"
)

// Handler wraps the distribution registry handler
type Handler struct {
	app *handlers.App
}

// NewHandler creates a new registry handler
func NewHandler(cfg *config.Config) (*Handler, error) {
	// Create distribution configuration
	distConfig := &configuration.Configuration{
		Version: "0.1",
		Storage: configuration.Storage{
			"filesystem": configuration.Parameters{
				"rootdirectory": cfg.Storage.Filesystem.RootDirectory,
			},
		},
		HTTP: configuration.HTTP{
			Addr: cfg.Server.Addr,
			Headers: http.Header{
				"X-Content-Type-Options": []string{"nosniff"},
			},
		},
		Auth: configuration.Auth{
			"token": configuration.Parameters{
				"realm":   cfg.Auth.Realm,
				"service": cfg.Auth.Service,
				"issuer":  cfg.Auth.Issuer,
			},
		},
	}

	// Set log level
	distConfig.Log.Level = "info"
	distConfig.Log.Formatter = "text"

	// Create registry app
	app, err := handlers.NewApp(context.Background(), distConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry app: %w", err)
	}

	return &Handler{
		app: app,
	}, nil
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.app.ServeHTTP(w, r)
}
