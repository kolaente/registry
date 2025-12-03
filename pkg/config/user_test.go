package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGeneratePassword(t *testing.T) {
	t.Run("returns non-empty string", func(t *testing.T) {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword() error = %v", err)
		}
		if pw == "" {
			t.Error("GeneratePassword() returned empty string")
		}
	})

	t.Run("generates different passwords each time", func(t *testing.T) {
		pw1, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword() error = %v", err)
		}

		pw2, err := GeneratePassword()
		if err != nil {
			t.Fatalf("GeneratePassword() error = %v", err)
		}

		if pw1 == pw2 {
			t.Error("GeneratePassword() returned same password twice")
		}
	})
}

func TestHashPassword(t *testing.T) {
	t.Run("produces bcrypt hash", func(t *testing.T) {
		password := "testpassword123"
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword() error = %v", err)
		}
		if !strings.HasPrefix(hash, "$2a$") {
			t.Errorf("HashPassword() hash = %v, doesn't look like bcrypt hash", hash)
		}
	})

	t.Run("hash verifies with correct password", func(t *testing.T) {
		password := "testpassword123"
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword() error = %v", err)
		}
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err != nil {
			t.Errorf("HashPassword() produced hash that doesn't verify: %v", err)
		}
	})

	t.Run("hash does not verify with wrong password", func(t *testing.T) {
		password := "testpassword123"
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword() error = %v", err)
		}
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrongpassword"))
		if err == nil {
			t.Error("HashPassword() hash verified with wrong password")
		}
	})
}

func TestAddUser(t *testing.T) {
	t.Run("adds user to existing users section", func(t *testing.T) {
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

		hashedPassword := "$2a$10$testhashedpassword"
		err = AddUser(configPath, "newuser", hashedPassword)
		if err != nil {
			t.Fatalf("AddUser() error = %v", err)
		}

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
	})

	t.Run("returns error for existing user", func(t *testing.T) {
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

		err = AddUser(configPath, "admin", "$2a$10$newhashedpassword")
		if err == nil {
			t.Error("AddUser() should return error for existing user")
		}

		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("AddUser() error = %v, want error containing 'already exists'", err)
		}
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		err := AddUser("/nonexistent/config.yaml", "newuser", "$2a$10$hash")
		if err == nil {
			t.Error("AddUser() should return error for nonexistent file")
		}
	})

	t.Run("creates users section if it does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

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

		hashedPassword := "$2a$10$testhashedpassword"
		err = AddUser(configPath, "newuser", hashedPassword)
		if err != nil {
			t.Fatalf("AddUser() error = %v", err)
		}

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
	})
}
