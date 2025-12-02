package registry

import (
	"context"
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
	// Note: We don't configure Auth here because we handle authentication
	// ourselves through middleware. Distribution will run without auth,
	// and our middleware will protect the endpoints.
	// We also don't set HTTP.Addr since we're wrapping the registry in our own HTTP server.
	distConfig := &configuration.Configuration{
		Version: "0.1",
		Storage: configuration.Storage{
			"filesystem": configuration.Parameters{
				"rootdirectory": cfg.Storage.Filesystem.RootDirectory,
			},
			"delete": configuration.Parameters{
				"enabled": true,
			},
		},
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
