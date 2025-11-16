package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/kolaente/registry/pkg/acl"
	"github.com/kolaente/registry/pkg/config"
	"github.com/kolaente/registry/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

// Handler handles authentication requests
type Handler struct {
	tokenService *TokenService
	aclMatcher   *acl.Matcher
	users        map[string]config.User
	realm        string
	service      string
}

// NewHandler creates a new auth handler
func NewHandler(tokenService *TokenService, aclMatcher *acl.Matcher, users map[string]config.User, realm, service string) *Handler {
	return &Handler{
		tokenService: tokenService,
		aclMatcher:   aclMatcher,
		users:        users,
		realm:        realm,
		service:      service,
	}
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

// ServeHTTP handles the /v2/token endpoint
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	scope := r.URL.Query().Get("scope")

	// Get credentials from basic auth
	username, password, ok := r.BasicAuth()
	if !ok || username == "" {
		h.unauthorized(w, "")
		return
	}

	// Pre-computed dummy hash for timing attack mitigation
	// Generated with: echo "dummy" | htpasswd -nbBC 10 dummy | cut -d: -f2
	// This ensures constant-time behavior even for non-existent users
	const dummyHash = "$2y$10$7YvdPKKXgNfU/ZrLnVPPIu5D8F6cQvKb6zWzNsLKJXZ9YvKQvZKgW"

	// Get user or prepare for constant-time comparison
	user, exists := h.users[username]
	hashToCheck := dummyHash
	if exists {
		hashToCheck = user.Password
	}

	// ALWAYS perform bcrypt comparison to ensure constant-time behavior
	// This prevents timing attacks that could be used to enumerate usernames
	err := bcrypt.CompareHashAndPassword([]byte(hashToCheck), []byte(password))

	// Only proceed if user exists AND password is correct
	if !exists || err != nil {
		// Log failed authentication attempt
		log.Printf("Failed authentication attempt for user '%s' from %s (user_exists=%v)",
			username, utils.GetClientIP(r), exists)
		h.unauthorized(w, "Invalid credentials")
		return
	}

	// Log successful authentication
	log.Printf("Successful authentication for user '%s' from %s", username, utils.GetClientIP(r))

	// Parse scope to determine requested access
	var accessEntries []AccessEntry

	if scope != "" {
		resourceType, name, requestedActions := acl.ParseScope(scope)

		if resourceType == "repository" && name != "" {
			// Check ACL permissions
			allowedActions := h.aclMatcher.GetAllowedActions(username, name)

			// Filter requested actions to only those that are allowed
			grantedActions := make([]string, 0)
			allowedMap := make(map[string]bool)
			for _, action := range allowedActions {
				allowedMap[action] = true
			}

			for _, action := range requestedActions {
				if allowedMap[action] {
					grantedActions = append(grantedActions, action)
				}
			}

			// Only add access entry if there are granted actions
			if len(grantedActions) > 0 {
				accessEntries = append(accessEntries, AccessEntry{
					Type:    resourceType,
					Name:    name,
					Actions: grantedActions,
				})
			}
		}
	}

	// Generate token
	token, err := h.tokenService.GenerateToken(username, accessEntries)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return token response
	response := TokenResponse{
		Token:       token,
		AccessToken: token,
		ExpiresIn:   300, // 5 minutes
		IssuedAt:    "",  // Optional
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// unauthorized sends a 401 Unauthorized response with WWW-Authenticate header
func (h *Handler) unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+h.realm+`"`)
	w.WriteHeader(http.StatusUnauthorized)
	if message != "" {
		w.Write([]byte(message))
	}
}

// AuthMiddleware validates tokens in incoming requests
type AuthMiddleware struct {
	tokenService *TokenService
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(tokenService *TokenService) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService: tokenService,
	}
}

// Middleware returns an HTTP middleware that validates tokens
func (am *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for token endpoint
		if strings.HasPrefix(r.URL.Path, "/v2/token") {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth for /v2/ ping (version check)
		if r.URL.Path == "/v2/" {
			next.ServeHTTP(w, r)
			return
		}

		// Get authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Check if this is a pull request (GET) - some clients don't send auth for public repos
			// For now, require auth for all requests
			w.Header().Set("WWW-Authenticate", `Bearer realm="/v2/token",service="registry"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		// Validate token
		claims, err := am.tokenService.ValidateToken(parts[1])
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="/v2/token",service="registry"`)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Token is valid - you could add claims to request context here if needed
		_ = claims

		next.ServeHTTP(w, r)
	})
}
