package gc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kolaente/registry/pkg/config"
)

func TestNewGarbageCollector(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &config.Config{
				Storage: config.StorageConfig{
					Filesystem: config.FilesystemStorage{
						RootDirectory: tmpDir,
					},
				},
				GarbageCollector: config.GarbageCollectorConfig{
					Enabled:        true,
					Interval:       "1h",
					RemoveUntagged: true,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid interval",
			config: &config.Config{
				Storage: config.StorageConfig{
					Filesystem: config.FilesystemStorage{
						RootDirectory: tmpDir,
					},
				},
				GarbageCollector: config.GarbageCollectorConfig{
					Enabled:        true,
					Interval:       "invalid",
					RemoveUntagged: true,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gc, err := NewGarbageCollector(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGarbageCollector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && gc == nil {
				t.Error("NewGarbageCollector() returned nil without error")
			}
		})
	}
}

func TestGarbageCollector_StartStop(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Filesystem: config.FilesystemStorage{
				RootDirectory: tmpDir,
			},
		},
		GarbageCollector: config.GarbageCollectorConfig{
			Enabled:        true,
			Interval:       "1h", // Long interval so it doesn't run during test
			RemoveUntagged: true,
		},
	}

	gc, err := NewGarbageCollector(cfg)
	if err != nil {
		t.Fatalf("NewGarbageCollector() error = %v", err)
	}

	// Start the garbage collector
	gc.Start()

	// Wait a bit to ensure the goroutine started
	time.Sleep(100 * time.Millisecond)

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		gc.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success - Stop completed
	case <-time.After(5 * time.Second):
		t.Error("GarbageCollector.Stop() timed out")
	}
}

func TestRunOnce(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the docker registry directory structure that the distribution expects
	repositoriesDir := filepath.Join(tmpDir, "docker", "registry", "v2", "repositories")
	blobsDir := filepath.Join(tmpDir, "docker", "registry", "v2", "blobs")
	err := os.MkdirAll(repositoriesDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create repositories directory: %v", err)
	}
	err = os.MkdirAll(blobsDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create blobs directory: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Filesystem: config.FilesystemStorage{
				RootDirectory: tmpDir,
			},
		},
	}

	ctx := context.Background()

	// Run garbage collection - should complete without error on empty registry
	err = RunOnce(ctx, cfg, true, true)
	if err != nil {
		t.Errorf("RunOnce() error = %v", err)
	}
}

func TestRunOnce_DryRun(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the docker registry directory structure that the distribution expects
	repositoriesDir := filepath.Join(tmpDir, "docker", "registry", "v2", "repositories")
	blobsDir := filepath.Join(tmpDir, "docker", "registry", "v2", "blobs")
	err := os.MkdirAll(repositoriesDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create repositories directory: %v", err)
	}
	err = os.MkdirAll(blobsDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create blobs directory: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Filesystem: config.FilesystemStorage{
				RootDirectory: tmpDir,
			},
		},
	}

	ctx := context.Background()

	// Run garbage collection in dry-run mode
	err = RunOnce(ctx, cfg, true, true)
	if err != nil {
		t.Errorf("RunOnce() with dry-run error = %v", err)
	}
}
