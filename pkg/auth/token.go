package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenService handles JWT token generation and validation
type TokenService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	service    string
}

// NewTokenService creates a new token service
func NewTokenService(issuer, service string) (*TokenService, error) {
	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &TokenService{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		issuer:     issuer,
		service:    service,
	}, nil
}

// NewTokenServiceFromFiles creates a token service from key files
func NewTokenServiceFromFiles(issuer, service, privateKeyPath, publicKeyPath string) (*TokenService, error) {
	ts := &TokenService{
		issuer:  issuer,
		service: service,
	}

	// Load private key
	if privateKeyPath != "" {
		privateKeyData, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}

		block, _ := pem.Decode(privateKeyData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block from private key")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 format
			key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
			var ok bool
			privateKey, ok = key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("key is not RSA private key")
			}
		}

		ts.privateKey = privateKey
		ts.publicKey = &privateKey.PublicKey
	}

	// Load public key if provided separately
	if publicKeyPath != "" && privateKeyPath == "" {
		publicKeyData, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key: %w", err)
		}

		block, _ := pem.Decode(publicKeyData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block from public key")
		}

		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			// Try PKIX format
			key, err2 := x509.ParsePKIXPublicKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
			var ok bool
			publicKey, ok = key.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("key is not RSA public key")
			}
		}

		ts.publicKey = publicKey
	}

	// If no keys provided, generate new ones
	if ts.privateKey == nil && ts.publicKey == nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		ts.privateKey = privateKey
		ts.publicKey = &privateKey.PublicKey
	}

	return ts, nil
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(ts.privateKey)
}

// ValidateToken validates a JWT token and returns the claims
func (ts *TokenService) ValidateToken(tokenString string) (*RegistryToken, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RegistryToken{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ts.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*RegistryToken); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// GetPublicKey returns the PEM-encoded public key
func (ts *TokenService) GetPublicKey() ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(ts.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}

// SaveKeys saves the private and public keys to files
func (ts *TokenService) SaveKeys(privateKeyPath, publicKeyPath string) error {
	// Save private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(ts.privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(ts.publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}
