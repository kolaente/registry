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

// createDriverAndRegistry creates a storage driver and registry for garbage collection
func createDriverAndRegistry(ctx context.Context, rootDirectory string) (storagedriver.StorageDriver, distribution.Namespace, error) {
	driver, err := factory.Create(ctx, "filesystem", map[string]interface{}{
		"rootdirectory": rootDirectory,
	})
	if err != nil {
		return nil, nil, err
	}

	registry, err := storage.NewRegistry(ctx, driver, storage.EnableDelete)
	if err != nil {
		return nil, nil, err
	}

	return driver, registry, nil
}

// runGCWithOptions performs garbage collection with the given options
func runGCWithOptions(ctx context.Context, driver storagedriver.StorageDriver, registry distribution.Namespace, opts storage.GCOpts) error {
	log.Println("Starting garbage collection...")
	start := time.Now()

	err := storage.MarkAndSweep(ctx, driver, registry, opts)
	if err != nil {
		return err
	}

	log.Printf("Garbage collection completed in %v", time.Since(start))
	return nil
}

// NewGarbageCollector creates a new garbage collector
func NewGarbageCollector(cfg *config.Config) (*GarbageCollector, error) {
	interval, err := time.ParseDuration(cfg.GarbageCollector.Interval)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	driver, registry, err := createDriverAndRegistry(ctx, cfg.Storage.Filesystem.RootDirectory)
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
	ctx := context.Background()
	err := runGCWithOptions(ctx, gc.driver, gc.registry, storage.GCOpts{
		DryRun:         false,
		RemoveUntagged: gc.removeUntagged,
		Quiet:          true,
	})

	if err != nil {
		log.Printf("Garbage collection failed: %v", err)
	}
}

// RunOnce performs a single garbage collection run (for CLI usage)
func RunOnce(ctx context.Context, cfg *config.Config, removeUntagged, dryRun bool) error {
	driver, registry, err := createDriverAndRegistry(ctx, cfg.Storage.Filesystem.RootDirectory)
	if err != nil {
		return err
	}

	return runGCWithOptions(ctx, driver, registry, storage.GCOpts{
		DryRun:         dryRun,
		RemoveUntagged: removeUntagged,
		Quiet:          false,
	})
}
