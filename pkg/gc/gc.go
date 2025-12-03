package gc

import (
	"context"
	"log"
	"time"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/registry/storage"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	"github.com/kolaente/registry/pkg/config"
)

// GarbageCollector runs periodic garbage collection on the registry storage
type GarbageCollector struct {
	driver         storagedriver.StorageDriver
	registry       distribution.Namespace
	interval       time.Duration
	removeUntagged bool
	stopCh         chan struct{}
	doneCh         chan struct{}
}

// NewGarbageCollector creates a new garbage collector
func NewGarbageCollector(cfg *config.Config) (*GarbageCollector, error) {
	interval, err := time.ParseDuration(cfg.GarbageCollector.Interval)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	// Create storage driver
	driver, err := factory.Create(ctx, "filesystem", map[string]interface{}{
		"rootdirectory": cfg.Storage.Filesystem.RootDirectory,
	})
	if err != nil {
		return nil, err
	}

	// Create registry
	registry, err := storage.NewRegistry(ctx, driver, storage.EnableDelete)
	if err != nil {
		return nil, err
	}

	return &GarbageCollector{
		driver:         driver,
		registry:       registry,
		interval:       interval,
		removeUntagged: cfg.GarbageCollector.RemoveUntagged,
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}, nil
}

// Start begins the periodic garbage collection
func (gc *GarbageCollector) Start() {
	go gc.run()
}

// Stop stops the garbage collector gracefully
func (gc *GarbageCollector) Stop() {
	close(gc.stopCh)
	<-gc.doneCh
}

func (gc *GarbageCollector) run() {
	defer close(gc.doneCh)

	ticker := time.NewTicker(gc.interval)
	defer ticker.Stop()

	// Run initial garbage collection at startup
	gc.runGC()

	for {
		select {
		case <-ticker.C:
			gc.runGC()
		case <-gc.stopCh:
			return
		}
	}
}

// runGC performs a single garbage collection run
func (gc *GarbageCollector) runGC() {
	log.Println("Starting garbage collection...")
	start := time.Now()

	ctx := context.Background()
	err := storage.MarkAndSweep(ctx, gc.driver, gc.registry, storage.GCOpts{
		DryRun:         false,
		RemoveUntagged: gc.removeUntagged,
		Quiet:          true,
	})

	if err != nil {
		log.Printf("Garbage collection failed: %v", err)
		return
	}

	log.Printf("Garbage collection completed in %v", time.Since(start))
}

// RunOnce performs a single garbage collection run (for CLI usage)
func RunOnce(ctx context.Context, cfg *config.Config, removeUntagged, dryRun bool) error {
	log.Println("Starting garbage collection...")
	start := time.Now()

	// Create storage driver
	driver, err := factory.Create(ctx, "filesystem", map[string]interface{}{
		"rootdirectory": cfg.Storage.Filesystem.RootDirectory,
	})
	if err != nil {
		return err
	}

	// Create registry
	registry, err := storage.NewRegistry(ctx, driver, storage.EnableDelete)
	if err != nil {
		return err
	}

	err = storage.MarkAndSweep(ctx, driver, registry, storage.GCOpts{
		DryRun:         dryRun,
		RemoveUntagged: removeUntagged,
		Quiet:          false,
	})

	if err != nil {
		return err
	}

	log.Printf("Garbage collection completed in %v", time.Since(start))
	return nil
}
