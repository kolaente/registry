package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGeneratePassword(t *testing.T) {
	pw1, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}

	// Should be a non-empty string
	if pw1 == "" {
		t.Error("GeneratePassword() returned empty string")
	}

	// Should generate different passwords each time
	pw2, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}

	if pw1 == pw2 {
		t.Error("GeneratePassword() returned same password twice")
	}
}

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	// Should be a bcrypt hash
	if !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("HashPassword() hash = %v, doesn't look like bcrypt hash", hash)
	}

	// Should be verifiable with bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		t.Errorf("HashPassword() produced hash that doesn't verify: %v", err)
	}

	// Should not verify with wrong password
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrongpassword"))
	if err == nil {
		t.Error("HashPassword() hash verified with wrong password")
	}
}

func TestAddUser(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `server:
  addr: ":5000"

users:
  admin:
    password: "$2y$10$hash"

acl:
  - account: "admin"
    name: "*"
    actions: ["*"]

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

	// Add a new user
	hashedPassword := "$2a$10$testhashedpassword"
	err = AddUser(configPath, "newuser", hashedPassword)
	if err != nil {
		t.Fatalf("AddUser() error = %v", err)
	}

	// Verify the user was added by loading the config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error after AddUser() = %v", err)
	}

	if len(cfg.Users) != 2 {
		t.Errorf("len(Users) = %v, want 2", len(cfg.Users))
	}

	user, ok := cfg.Users["newuser"]
	if !ok {
		t.Error("newuser not found in config after AddUser()")
	}

	if user.Password != hashedPassword {
		t.Errorf("newuser.Password = %v, want %v", user.Password, hashedPassword)
	}
}

func TestAddUser_UserAlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `users:
  admin:
    password: "$2y$10$hash"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Try to add existing user
	err = AddUser(configPath, "admin", "$2a$10$newhashedpassword")
	if err == nil {
		t.Error("AddUser() should return error for existing user")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("AddUser() error = %v, want error containing 'already exists'", err)
	}
}

func TestAddUser_FileNotFound(t *testing.T) {
	err := AddUser("/nonexistent/config.yaml", "newuser", "$2a$10$hash")
	if err == nil {
		t.Error("AddUser() should return error for nonexistent file")
	}
}

func TestAddUser_CreatesUsersSection(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Config without users section
	configContent := `server:
  addr: ":5000"

storage:
  filesystem:
    rootdirectory: "/data/registry"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Add a user (should create users section)
	hashedPassword := "$2a$10$testhashedpassword"
	err = AddUser(configPath, "newuser", hashedPassword)
	if err != nil {
		t.Fatalf("AddUser() error = %v", err)
	}

	// Verify the user was added
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error after AddUser() = %v", err)
	}

	if len(cfg.Users) != 1 {
		t.Errorf("len(Users) = %v, want 1", len(cfg.Users))
	}

	user, ok := cfg.Users["newuser"]
	if !ok {
		t.Error("newuser not found in config after AddUser()")
	}

	if user.Password != hashedPassword {
		t.Errorf("newuser.Password = %v, want %v", user.Password, hashedPassword)
	}
}
