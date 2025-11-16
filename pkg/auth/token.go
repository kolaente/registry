package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenService handles JWT token generation and validation
type TokenService struct {
	// HMAC secret (for symmetric signing)
	hmacSecret []byte

	issuer  string
	service string
}

// NewTokenService creates a new token service with HMAC signing
func NewTokenService(issuer, service, hmacSecret string) (*TokenService, error) {
	if hmacSecret == "" {
		return nil, fmt.Errorf("HMAC secret is required")
	}

	return &TokenService{
		hmacSecret: []byte(hmacSecret),
		issuer:     issuer,
		service:    service,
	}, nil
}

// NewTokenServiceFromConfig creates a token service from configuration
func NewTokenServiceFromConfig(issuer, service, hmacSecret string) (*TokenService, error) {
	return NewTokenService(issuer, service, hmacSecret)
}

// RegistryToken represents the JWT claims for Docker registry authentication
type RegistryToken struct {
	jwt.RegisteredClaims
	Access []AccessEntry `json:"access,omitempty"`
}

// AccessEntry represents a single access entry in the token
type AccessEntry struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// GenerateToken creates a new JWT token with the specified claims
func (ts *TokenService) GenerateToken(account string, access []AccessEntry) (string, error) {
	now := time.Now()
	claims := RegistryToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   account,
			Audience:  jwt.ClaimStrings{ts.service},
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Access: access,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(ts.hmacSecret)
}

// ValidateToken validates a JWT token and returns the claims
func (ts *TokenService) ValidateToken(tokenString string) (*RegistryToken, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RegistryToken{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v (expected HMAC)", token.Header["alg"])
		}
		return ts.hmacSecret, nil
	})

	if err != nil {
		// Provide specific error messages for common JWT errors
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, fmt.Errorf("token expired")
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, fmt.Errorf("token not valid yet")
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, fmt.Errorf("token signature verification failed")
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, fmt.Errorf("malformed token")
		default:
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}
	}

	if claims, ok := token.Claims.(*RegistryToken); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

