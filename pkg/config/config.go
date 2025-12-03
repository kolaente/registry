package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Server           ServerConfig           `yaml:"server"`
	Users            map[string]User        `yaml:"users"`
	ACL              []ACLRule              `yaml:"acl"`
	Storage          StorageConfig          `yaml:"storage"`
	Auth             AuthConfig             `yaml:"auth"`
	RateLimit        RateLimitConfig        `yaml:"rate_limit"`
	GarbageCollector GarbageCollectorConfig `yaml:"garbage_collector"`
}

// ServerConfig holds server-specific settings
type ServerConfig struct {
	Addr string `yaml:"addr"`
}

// User represents a user account
type User struct {
	Password string `yaml:"password"` // bcrypt hash
}

// ACLRule defines access control rules
type ACLRule struct {
	Account string   `yaml:"account"`
	Name    string   `yaml:"name"`    // Repository name pattern (supports wildcards)
	Actions []string `yaml:"actions"` // pull, push, delete, or *
}

// StorageConfig defines where to store registry data
type StorageConfig struct {
	Filesystem FilesystemStorage `yaml:"filesystem"`
	S3         S3Storage         `yaml:"s3"`
}

// FilesystemStorage configures filesystem storage
type FilesystemStorage struct {
	RootDirectory string `yaml:"rootdirectory"`
}

// S3Storage configures S3 storage
type S3Storage struct {
	AccessKey      string `yaml:"accesskey"`
	SecretKey      string `yaml:"secretkey"`
	Region         string `yaml:"region"`
	RegionEndpoint string `yaml:"regionendpoint"`
	Bucket         string `yaml:"bucket"`
	RootDirectory  string `yaml:"rootdirectory"`
	Encrypt        bool   `yaml:"encrypt"`
	Secure         bool   `yaml:"secure"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Realm      string `yaml:"realm"`
	Service    string `yaml:"service"`
	Issuer     string `yaml:"issuer"`
	HMACSecret string `yaml:"hmac_secret"` // HMAC secret key for JWT signing
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	Enabled        bool    `yaml:"enabled"`          // Enable/disable rate limiting
	RequestsPerSec float64 `yaml:"requests_per_sec"` // Requests per second per IP
	Burst          int     `yaml:"burst"`            // Burst size
}

// GarbageCollectorConfig holds garbage collection settings
type GarbageCollectorConfig struct {
	Enabled        bool   `yaml:"enabled"`         // Enable/disable automatic garbage collection
	Interval       string `yaml:"interval"`        // Interval between garbage collection runs (e.g., "24h", "1h30m")
	RemoveUntagged bool   `yaml:"remove_untagged"` // Remove untagged manifests during garbage collection
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if cfg.Server.Addr == "" {
		cfg.Server.Addr = ":5000"
	}
	if cfg.Auth.Realm == "" {
		cfg.Auth.Realm = "Registry"
	}
	if cfg.Auth.Service == "" {
		cfg.Auth.Service = "Docker Registry"
	}
	if cfg.Auth.Issuer == "" {
		cfg.Auth.Issuer = "registry-auth-server"
	}

	// Only set filesystem root directory default if S3 is not configured
	if cfg.Storage.S3.Bucket == "" && cfg.Storage.Filesystem.RootDirectory == "" {
		cfg.Storage.Filesystem.RootDirectory = "/data/registry"
	}

	// S3 defaults
	if cfg.Storage.S3.Bucket != "" {
		if cfg.Storage.S3.Region == "" {
			cfg.Storage.S3.Region = "us-east-1"
		}
		// Default secure to true for S3 connections
		// Note: secure field defaults to false (Go zero value), so we can't detect if it was explicitly set
	}

	// Rate limit defaults
	if cfg.RateLimit.RequestsPerSec == 0 {
		cfg.RateLimit.RequestsPerSec = 10 // 10 requests/sec default
	}
	if cfg.RateLimit.Burst == 0 {
		cfg.RateLimit.Burst = 20 // Burst of 20 requests
	}

	// Garbage collector defaults
	if cfg.GarbageCollector.Interval == "" {
		cfg.GarbageCollector.Interval = "24h" // Default to daily
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if len(c.Users) == 0 {
		return fmt.Errorf("at least one user must be defined")
	}

	// Validate storage configuration: either filesystem or S3 must be configured
	hasFilesystem := c.Storage.Filesystem.RootDirectory != ""
	hasS3 := c.Storage.S3.Bucket != ""

	if !hasFilesystem && !hasS3 {
		return fmt.Errorf("storage configuration required: either filesystem.rootdirectory or s3.bucket must be set")
	}

	// Validate S3 configuration if S3 is being used
	if hasS3 {
		if c.Storage.S3.Region == "" {
			return fmt.Errorf("storage.s3.region must be set when using S3 storage")
		}
	}

	// Validate authentication configuration
	if c.Auth.HMACSecret == "" {
		return fmt.Errorf("auth.hmac_secret must be provided")
	}

	// Validate ACL rules
	for i, rule := range c.ACL {
		if rule.Account == "" {
			return fmt.Errorf("ACL rule %d: account cannot be empty", i)
		}
		if rule.Name == "" {
			return fmt.Errorf("ACL rule %d: name cannot be empty", i)
		}
		if len(rule.Actions) == 0 {
			return fmt.Errorf("ACL rule %d: at least one action must be specified", i)
		}
	}

	// Validate garbage collector configuration
	if c.GarbageCollector.Enabled {
		if _, err := time.ParseDuration(c.GarbageCollector.Interval); err != nil {
			return fmt.Errorf("garbage_collector.interval is invalid: %w", err)
		}
	}

	return nil
}
