package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  addr: ":5000"

users:
  admin:
    password: "$2y$10$hash"
  developer:
    password: "$2y$10$hash2"

acl:
  - account: "admin"
    name: "*"
    actions: ["*"]
  - account: "developer"
    name: "myorg/*"
    actions: ["pull", "push"]

storage:
  filesystem:
    rootdirectory: "/data/registry"

auth:
  realm: "Registry"
  service: "Docker Registry"
  issuer: "test-issuer"
  hmac_secret: "test-secret-key"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Test server config
	if cfg.Server.Addr != ":5000" {
		t.Errorf("Server.Addr = %v, want :5000", cfg.Server.Addr)
	}

	// Test users
	if len(cfg.Users) != 2 {
		t.Errorf("len(Users) = %v, want 2", len(cfg.Users))
	}
	if _, ok := cfg.Users["admin"]; !ok {
		t.Error("admin user not found")
	}
	if _, ok := cfg.Users["developer"]; !ok {
		t.Error("developer user not found")
	}

	// Test ACL
	if len(cfg.ACL) != 2 {
		t.Errorf("len(ACL) = %v, want 2", len(cfg.ACL))
	}
	if cfg.ACL[0].Account != "admin" {
		t.Errorf("ACL[0].Account = %v, want admin", cfg.ACL[0].Account)
	}

	// Test storage
	if cfg.Storage.Filesystem.RootDirectory != "/data/registry" {
		t.Errorf("Storage.Filesystem.RootDirectory = %v, want /data/registry", cfg.Storage.Filesystem.RootDirectory)
	}

	// Test auth
	if cfg.Auth.Realm != "Registry" {
		t.Errorf("Auth.Realm = %v, want Registry", cfg.Auth.Realm)
	}
	if cfg.Auth.Service != "Docker Registry" {
		t.Errorf("Auth.Service = %v, want Docker Registry", cfg.Auth.Service)
	}
	if cfg.Auth.Issuer != "test-issuer" {
		t.Errorf("Auth.Issuer = %v, want test-issuer", cfg.Auth.Issuer)
	}
}

func TestLoad_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Minimal config to test defaults
	configContent := `
users:
  admin:
    password: "$2y$10$hash"

acl:
  - account: "admin"
    name: "*"
    actions: ["*"]
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Test defaults
	if cfg.Server.Addr != ":5000" {
		t.Errorf("Default Server.Addr = %v, want :5000", cfg.Server.Addr)
	}
	if cfg.Auth.Realm != "Registry" {
		t.Errorf("Default Auth.Realm = %v, want Registry", cfg.Auth.Realm)
	}
	if cfg.Auth.Service != "Docker Registry" {
		t.Errorf("Default Auth.Service = %v, want Docker Registry", cfg.Auth.Service)
	}
	if cfg.Auth.Issuer != "registry-auth-server" {
		t.Errorf("Default Auth.Issuer = %v, want registry-auth-server", cfg.Auth.Issuer)
	}
	if cfg.Storage.Filesystem.RootDirectory != "/data/registry" {
		t.Errorf("Default Storage.Filesystem.RootDirectory = %v, want /data/registry", cfg.Storage.Filesystem.RootDirectory)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("Load() with nonexistent file should return error")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	invalidContent := `
server:
  addr: ":5000"
  invalid yaml here
users
`

	err := os.WriteFile(configPath, []byte(invalidContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err = Load(configPath)
	if err == nil {
		t.Error("Load() with invalid YAML should return error")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Users: map[string]User{
					"admin": {Password: "$2y$10$hash"},
				},
				ACL: []ACLRule{
					{Account: "admin", Name: "*", Actions: []string{"*"}},
				},
				Storage: StorageConfig{
					Filesystem: FilesystemStorage{
						RootDirectory: "/data/registry",
					},
				},
				Auth: AuthConfig{
					HMACSecret: "test-secret",
				},
			},
			wantErr: false,
		},
		{
			name: "no users",
			config: &Config{
				Users: map[string]User{},
				ACL: []ACLRule{
					{Account: "admin", Name: "*", Actions: []string{"*"}},
				},
				Storage: StorageConfig{
					Filesystem: FilesystemStorage{
						RootDirectory: "/data/registry",
					},
				},
				Auth: AuthConfig{
					HMACSecret: "test-secret",
				},
			},
			wantErr: true,
		},
		{
			name: "no storage directory",
			config: &Config{
				Users: map[string]User{
					"admin": {Password: "$2y$10$hash"},
				},
				ACL: []ACLRule{
					{Account: "admin", Name: "*", Actions: []string{"*"}},
				},
				Storage: StorageConfig{
					Filesystem: FilesystemStorage{
						RootDirectory: "",
					},
				},
				Auth: AuthConfig{
					HMACSecret: "test-secret",
				},
			},
			wantErr: true,
		},
		{
			name: "no hmac_secret",
			config: &Config{
				Users: map[string]User{
					"admin": {Password: "$2y$10$hash"},
				},
				ACL: []ACLRule{
					{Account: "admin", Name: "*", Actions: []string{"*"}},
				},
				Storage: StorageConfig{
					Filesystem: FilesystemStorage{
						RootDirectory: "/data/registry",
					},
				},
				Auth: AuthConfig{
					HMACSecret: "",
				},
			},
			wantErr: true,
		},
		{
			name: "ACL rule without account",
			config: &Config{
				Users: map[string]User{
					"admin": {Password: "$2y$10$hash"},
				},
				ACL: []ACLRule{
					{Account: "", Name: "*", Actions: []string{"*"}},
				},
				Storage: StorageConfig{
					Filesystem: FilesystemStorage{
						RootDirectory: "/data/registry",
					},
				},
				Auth: AuthConfig{
					HMACSecret: "test-secret",
				},
			},
			wantErr: true,
		},
		{
			name: "ACL rule without name",
			config: &Config{
				Users: map[string]User{
					"admin": {Password: "$2y$10$hash"},
				},
				ACL: []ACLRule{
					{Account: "admin", Name: "", Actions: []string{"*"}},
				},
				Storage: StorageConfig{
					Filesystem: FilesystemStorage{
						RootDirectory: "/data/registry",
					},
				},
				Auth: AuthConfig{
					HMACSecret: "test-secret",
				},
			},
			wantErr: true,
		},
		{
			name: "ACL rule without actions",
			config: &Config{
				Users: map[string]User{
					"admin": {Password: "$2y$10$hash"},
				},
				ACL: []ACLRule{
					{Account: "admin", Name: "*", Actions: []string{}},
				},
				Storage: StorageConfig{
					Filesystem: FilesystemStorage{
						RootDirectory: "/data/registry",
					},
				},
				Auth: AuthConfig{
					HMACSecret: "test-secret",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
