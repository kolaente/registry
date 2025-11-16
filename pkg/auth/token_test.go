package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewTokenService(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service", "test-secret")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	if ts.issuer != "test-issuer" {
		t.Errorf("issuer = %v, want test-issuer", ts.issuer)
	}
	if ts.service != "test-service" {
		t.Errorf("service = %v, want test-service", ts.service)
	}
	if string(ts.hmacSecret) != "test-secret" {
		t.Error("hmacSecret should be set correctly")
	}
}

func TestTokenService_GenerateAndValidateToken(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service", "test-secret")
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
	ts, err := NewTokenService("test-issuer", "test-service", "test-secret")
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
	ts1, err := NewTokenService("test-issuer", "test-service", "secret1")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	ts2, err := NewTokenService("test-issuer", "test-service", "secret2")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	// Generate token with ts1
	token, err := ts1.GenerateToken("testuser", nil)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	// Try to validate with ts2 (different secret)
	_, err = ts2.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should fail with wrong secret")
	}
}

func TestNewTokenServiceFromConfig(t *testing.T) {
	hmacSecret := "test-secret-key-for-hmac-signing"

	ts, err := NewTokenServiceFromConfig("test-issuer", "test-service", hmacSecret)
	if err != nil {
		t.Fatalf("NewTokenServiceFromConfig() error = %v", err)
	}

	if string(ts.hmacSecret) != hmacSecret {
		t.Errorf("hmacSecret not set correctly")
	}
}

func TestNewTokenService_EmptySecret(t *testing.T) {
	_, err := NewTokenService("test-issuer", "test-service", "")
	if err == nil {
		t.Error("NewTokenService() should error with empty HMAC secret")
	}
}

func TestTokenService_TokenExpiration(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service", "test-secret")
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

func TestTokenService_WrongSigningMethod(t *testing.T) {
	ts, err := NewTokenService("test-issuer", "test-service", "test-secret")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	// Create a token with wrong signing method (RS256 instead of HS256)
	claims := RegistryToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "test-issuer",
			Subject: "testuser",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// We need a dummy RSA key for this test
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Try to validate - should fail due to wrong signing method
	_, err = ts.ValidateToken(tokenString)
	if err == nil {
		t.Error("ValidateToken() should fail with wrong signing method")
	}
}
