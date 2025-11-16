package auth

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewTokenService(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	if ts.issuer != "test-issuer" {
		t.Errorf("issuer = %v, want test-issuer", ts.issuer)
	}
	if ts.service != "test-service" {
		t.Errorf("service = %v, want test-service", ts.service)
	}
	if ts.privateKey == nil {
		t.Error("privateKey should not be nil")
	}
	if ts.publicKey == nil {
		t.Error("publicKey should not be nil")
	}
}

func TestTokenService_GenerateAndValidateToken(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	access := []AccessEntry{
		{
			Type:    "repository",
			Name:    "myorg/app",
			Actions: []string{"pull", "push"},
		},
	}

	// Generate token
	tokenString, err := ts.GenerateToken("testuser", access)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if tokenString == "" {
		t.Error("GenerateToken() returned empty token")
	}

	// Validate token
	claims, err := ts.ValidateToken(tokenString)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.Subject != "testuser" {
		t.Errorf("Subject = %v, want testuser", claims.Subject)
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("Issuer = %v, want test-issuer", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "test-service" {
		t.Errorf("Audience = %v, want [test-service]", claims.Audience)
	}
	if len(claims.Access) != 1 {
		t.Fatalf("len(Access) = %v, want 1", len(claims.Access))
	}
	if claims.Access[0].Type != "repository" {
		t.Errorf("Access[0].Type = %v, want repository", claims.Access[0].Type)
	}
	if claims.Access[0].Name != "myorg/app" {
		t.Errorf("Access[0].Name = %v, want myorg/app", claims.Access[0].Name)
	}
}

func TestTokenService_ValidateToken_InvalidToken(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "invalid format",
			token: "invalid.token.format",
		},
		{
			name:  "malformed JWT",
			token: "not-a-jwt-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ts.ValidateToken(tt.token)
			if err == nil {
				t.Error("ValidateToken() should return error for invalid token")
			}
		})
	}
}

func TestTokenService_ValidateToken_WrongSignature(t *testing.T) {
	ts1, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	ts2, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	// Generate token with ts1
	token, err := ts1.GenerateToken("testuser", nil)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	// Try to validate with ts2 (different key)
	_, err = ts2.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should fail with wrong key")
	}
}

func TestTokenService_SaveAndLoadKeys(t *testing.T) {
	tmpDir := t.TempDir()
	privateKeyPath := filepath.Join(tmpDir, "private.key")
	publicKeyPath := filepath.Join(tmpDir, "public.key")

	// Create and save keys
	ts1, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	err = ts1.SaveKeys(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("SaveKeys() error = %v", err)
	}

	// Check files exist
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Error("private key file was not created")
	}
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		t.Error("public key file was not created")
	}

	// Load keys into new service
	ts2, err := NewTokenServiceFromFiles("test-issuer", "test-service", privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("NewTokenServiceFromFiles() error = %v", err)
	}

	// Generate token with ts1
	token, err := ts1.GenerateToken("testuser", nil)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	// Validate with ts2 (should work because keys are the same)
	claims, err := ts2.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.Subject != "testuser" {
		t.Errorf("Subject = %v, want testuser", claims.Subject)
	}
}

func TestTokenService_LoadNonexistentKeys(t *testing.T) {
	tmpDir := t.TempDir()
	privateKeyPath := filepath.Join(tmpDir, "nonexistent_private.key")
	publicKeyPath := filepath.Join(tmpDir, "nonexistent_public.key")

	// Should generate new keys if files don't exist
	ts, err := NewTokenServiceFromFiles("test-issuer", "test-service", privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("NewTokenServiceFromFiles() should not error when keys don't exist: %v", err)
	}

	if ts.privateKey == nil {
		t.Error("privateKey should be generated when file doesn't exist")
	}
	if ts.publicKey == nil {
		t.Error("publicKey should be generated when file doesn't exist")
	}
}

func TestTokenService_GetPublicKey(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	pubKeyPEM, err := ts.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	// Parse PEM
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %v, want PUBLIC KEY", block.Type)
	}

	// Parse public key
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
}

func TestTokenService_TokenExpiration(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	token, err := ts.GenerateToken("testuser", nil)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims, err := ts.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Check expiration is set to ~5 minutes from now
	expiresAt := claims.ExpiresAt.Time
	now := time.Now()
	expectedExpiry := now.Add(5 * time.Minute)

	// Allow 10 second variance
	if expiresAt.Before(expectedExpiry.Add(-10*time.Second)) || expiresAt.After(expectedExpiry.Add(10*time.Second)) {
		t.Errorf("ExpiresAt = %v, want ~%v", expiresAt, expectedExpiry)
	}
}

func TestTokenService_InvalidPrivateKeyFormat(t *testing.T) {
	tmpDir := t.TempDir()
	privateKeyPath := filepath.Join(tmpDir, "invalid.key")

	// Write invalid key format
	err := os.WriteFile(privateKeyPath, []byte("not a valid key"), 0600)
	if err != nil {
		t.Fatalf("Failed to write invalid key: %v", err)
	}

	_, err = NewTokenServiceFromFiles("test-issuer", "test-service", privateKeyPath, "")
	if err == nil {
		t.Error("NewTokenServiceFromFiles() should error with invalid key format")
	}
}

func TestAccessEntry(t *testing.T) {
	// Test that AccessEntry can be marshaled/unmarshaled correctly
	entry := AccessEntry{
		Type:    "repository",
		Name:    "myorg/app",
		Actions: []string{"pull", "push"},
	}

	// This is implicitly tested in token generation/validation,
	// but we can verify the structure
	if entry.Type != "repository" {
		t.Errorf("Type = %v, want repository", entry.Type)
	}
	if entry.Name != "myorg/app" {
		t.Errorf("Name = %v, want myorg/app", entry.Name)
	}
	if len(entry.Actions) != 2 {
		t.Errorf("len(Actions) = %v, want 2", len(entry.Actions))
	}
}

func TestRegistryToken_Claims(t *testing.T) {
	now := time.Now()
	token := RegistryToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "testuser",
			Audience:  jwt.ClaimStrings{"test-service"},
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Access: []AccessEntry{
			{Type: "repository", Name: "test/repo", Actions: []string{"pull"}},
		},
	}

	if token.Issuer != "test-issuer" {
		t.Errorf("Issuer = %v, want test-issuer", token.Issuer)
	}
	if token.Subject != "testuser" {
		t.Errorf("Subject = %v, want testuser", token.Subject)
	}
	if len(token.Access) != 1 {
		t.Errorf("len(Access) = %v, want 1", len(token.Access))
	}
}

func TestNewTokenServiceFromFiles_PKCS8(t *testing.T) {
	tmpDir := t.TempDir()
	privateKeyPath := filepath.Join(tmpDir, "private_pkcs8.key")

	// Generate a key and save it in PKCS8 format
	ts1, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	// Save as PKCS8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(ts1.privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	err = os.WriteFile(privateKeyPath, privateKeyPEM, 0600)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Load it
	ts2, err := NewTokenServiceFromFiles("test-issuer", "test-service", privateKeyPath, "")
	if err != nil {
		t.Fatalf("NewTokenServiceFromFiles() error = %v", err)
	}

	// Verify it works
	if ts2.privateKey == nil {
		t.Error("privateKey should be loaded")
	}

	// Generate and validate token
	token, err := ts2.GenerateToken("testuser", nil)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = ts2.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
}

func TestNewTokenServiceFromFiles_InvalidRSAKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid_rsa.key")

	// Create a non-RSA key (this would be something like an EC key in real scenario)
	// For testing, we'll just write an invalid PEM that decodes but isn't RSA
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not actually a key"),
	})

	err := os.WriteFile(keyPath, invalidPEM, 0600)
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = NewTokenServiceFromFiles("test-issuer", "test-service", keyPath, "")
	if err == nil {
		t.Error("NewTokenServiceFromFiles() should error with invalid RSA key")
	}
}

func TestTokenService_WrongSigningMethod(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	// Create a token with wrong signing method (HS256 instead of RS256)
	claims := RegistryToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "test-issuer",
			Subject: "testuser",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Try to validate - should fail due to wrong signing method
	_, err = ts.ValidateToken(tokenString)
	if err == nil {
		t.Error("ValidateToken() should fail with wrong signing method")
	}
}
