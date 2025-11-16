package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kolaente/registry/pkg/acl"
	"github.com/kolaente/registry/pkg/config"
	"github.com/kolaente/registry/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

var (
	// Regex to extract repository name from Docker Registry V2 API paths
	repoPathRegex = regexp.MustCompile(`^/v2/([^/]+(?:/[^/]+)*?)/(manifests|blobs|tags)`)
)

// extractRepositoryFromPath extracts the repository name from a Docker Registry V2 API path
func extractRepositoryFromPath(path string) string {
	matches := repoPathRegex.FindStringSubmatch(path)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

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
		log.Printf("Authentication failed: no credentials provided from %s", utils.GetClientIP(r))
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
			deniedActions := make([]string, 0)
			allowedMap := make(map[string]bool)
			for _, action := range allowedActions {
				allowedMap[action] = true
			}

			for _, action := range requestedActions {
				if allowedMap[action] {
					grantedActions = append(grantedActions, action)
				} else {
					deniedActions = append(deniedActions, action)
				}
			}

			// Log ACL denials
			if len(deniedActions) > 0 {
				log.Printf("ACL denied access for user '%s' to repository '%s' for actions %v from %s (allowed_actions=%v)",
					username, name, deniedActions, utils.GetClientIP(r), allowedActions)
			}

			// Only add access entry if there are granted actions
			if len(grantedActions) > 0 {
				accessEntries = append(accessEntries, AccessEntry{
					Type:    resourceType,
					Name:    name,
					Actions: grantedActions,
				})
			} else {
				// All requested actions were denied
				log.Printf("ACL denied all access for user '%s' to repository '%s': requested %v but no matching ACL rule from %s",
					username, name, requestedActions, utils.GetClientIP(r))
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
		IssuedAt:    time.Now().UTC().Format(time.RFC3339),
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
	service      string
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(tokenService *TokenService, service string) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService: tokenService,
		service:      service,
	}
}

func getAuthHeaderFromRepoContext(r *http.Request) string {
	// Construct the full token URL from the request
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	tokenURL := fmt.Sprintf("%s://%s/v2/token", scheme, r.Host)

	// Extract repository name from path and build scope
	var wwwAuthHeader string
	repoName := extractRepositoryFromPath(r.URL.Path)
	if repoName != "" {
		// Determine actions based on HTTP method
		actions := "pull"
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.Method == "DELETE" {
			actions = "pull,push"
		}
		scope := fmt.Sprintf("repository:%s:%s", repoName, actions)
		return fmt.Sprintf(`Bearer realm="%s",service="%s",scope="%s"`, tokenURL, am.service, scope)
	}

	// Fallback without scope if we can't parse the repo name
	return fmt.Sprintf(`Bearer realm="%s",service="%s"`, tokenURL, am.service)

}

// Middleware returns an HTTP middleware that validates tokens
func (am *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for token endpoint
		if strings.HasPrefix(r.URL.Path, "/v2/token") {
			next.ServeHTTP(w, r)
			return
		}

		// Get authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			wwwAuthHeader := getAuthHeaderFromRepoContext(r)
			w.Header().Set("WWW-Authenticate", wwwAuthHeader)
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
		_, err := am.tokenService.ValidateToken(parts[1])
		if err != nil {
			wwwAuthHeader := getAuthHeaderFromRepoContext(r)
			w.Header().Set("WWW-Authenticate", wwwAuthHeader)
			http.Error(w, "Invalid token", http.StatusUnauthorized)

			return
		}

		// Token is valid
		next.ServeHTTP(w, r)
	})
}
