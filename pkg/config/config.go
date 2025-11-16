package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Server    ServerConfig      `yaml:"server"`
	Users     map[string]User   `yaml:"users"`
	ACL       []ACLRule         `yaml:"acl"`
	Storage   StorageConfig     `yaml:"storage"`
	Auth      AuthConfig        `yaml:"auth"`
	RateLimit RateLimitConfig   `yaml:"rate_limit"`
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
}

// FilesystemStorage configures filesystem storage
type FilesystemStorage struct {
	RootDirectory string `yaml:"rootdirectory"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Realm         string `yaml:"realm"`
	Service       string `yaml:"service"`
	Issuer        string `yaml:"issuer"`
	SigningMethod string `yaml:"signing_method"` // "rsa" or "hmac" (default: "rsa")

	// RSA keys (used when signing_method = "rsa")
	PrivateKey string `yaml:"private_key"` // Path to RSA private key
	PublicKey  string `yaml:"public_key"`  // Path to RSA public key

	// HMAC secret (used when signing_method = "hmac")
	HMACSecret string `yaml:"hmac_secret"` // HMAC secret key
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	Enabled        bool    `yaml:"enabled"`          // Enable/disable rate limiting
	RequestsPerSec float64 `yaml:"requests_per_sec"` // Requests per second per IP
	Burst          int     `yaml:"burst"`            // Burst size
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
	if cfg.Auth.SigningMethod == "" {
		cfg.Auth.SigningMethod = "rsa" // Default to RSA for backward compatibility
	}
	if cfg.Storage.Filesystem.RootDirectory == "" {
		cfg.Storage.Filesystem.RootDirectory = "/data/registry"
	}

	// Rate limit defaults
	if cfg.RateLimit.RequestsPerSec == 0 {
		cfg.RateLimit.RequestsPerSec = 10 // 10 requests/sec default
	}
	if cfg.RateLimit.Burst == 0 {
		cfg.RateLimit.Burst = 20 // Burst of 20 requests
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if len(c.Users) == 0 {
		return fmt.Errorf("at least one user must be defined")
	}

	if c.Storage.Filesystem.RootDirectory == "" {
		return fmt.Errorf("storage root directory must be set")
	}

	// Validate authentication configuration
	// Empty signing_method is allowed (defaults to "rsa" in Load)
	if c.Auth.SigningMethod != "" && c.Auth.SigningMethod != "rsa" && c.Auth.SigningMethod != "hmac" {
		return fmt.Errorf("auth.signing_method must be either 'rsa' or 'hmac', got: %s", c.Auth.SigningMethod)
	}

	if c.Auth.SigningMethod == "hmac" {
		if c.Auth.HMACSecret == "" {
			return fmt.Errorf("auth.hmac_secret must be provided when signing_method is 'hmac'")
		}
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

	return nil
}
