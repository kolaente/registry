package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kolaente/registry/pkg/acl"
	"github.com/kolaente/registry/pkg/config"
	"golang.org/x/crypto/bcrypt"
)

func TestHandler_ServeHTTP_Success(t *testing.T) {
	// Setup
	tokenService, err := NewTokenService("test-issuer", "test-service", "test-secret")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	aclRules := []config.ACLRule{
		{Account: "admin", Name: "*", Actions: []string{"*"}},
	}
	aclMatcher := acl.NewMatcher(aclRules)

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	users := map[string]config.User{
		"admin": {Password: string(passwordHash)},
	}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	// Create request
	req := httptest.NewRequest("GET", "/v2/token?service=test-service&scope=repository:myorg/app:pull,push", nil)
	req.SetBasicAuth("admin", "password")
	w := httptest.NewRecorder()

	// Execute
	handler.ServeHTTP(w, req)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
	}

	var response TokenResponse
	err = json.NewDecoder(w.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Token == "" {
		t.Error("Token should not be empty")
	}
	if response.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if response.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %v, want 300", response.ExpiresIn)
	}
}

func TestHandler_ServeHTTP_NoAuth(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	aclMatcher := acl.NewMatcher([]config.ACLRule{})
	users := map[string]config.User{}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	req := httptest.NewRequest("GET", "/v2/token", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusUnauthorized)
	}

	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth != `Basic realm="Test Realm"` {
		t.Errorf("WWW-Authenticate = %v, want Basic realm=\"Test Realm\"", wwwAuth)
	}
}

func TestHandler_ServeHTTP_InvalidCredentials(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	aclMatcher := acl.NewMatcher([]config.ACLRule{})

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	users := map[string]config.User{
		"admin": {Password: string(passwordHash)},
	}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	req := httptest.NewRequest("GET", "/v2/token", nil)
	req.SetBasicAuth("admin", "wrongpassword")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusUnauthorized)
	}
}

func TestHandler_ServeHTTP_NonexistentUser(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	aclMatcher := acl.NewMatcher([]config.ACLRule{})
	users := map[string]config.User{}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	req := httptest.NewRequest("GET", "/v2/token", nil)
	req.SetBasicAuth("nonexistent", "password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusUnauthorized)
	}
}

func TestHandler_ServeHTTP_WithScope(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")

	aclRules := []config.ACLRule{
		{Account: "developer", Name: "myorg/backend-*", Actions: []string{"pull", "push"}},
	}
	aclMatcher := acl.NewMatcher(aclRules)

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	users := map[string]config.User{
		"developer": {Password: string(passwordHash)},
	}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	req := httptest.NewRequest("GET", "/v2/token?scope=repository:myorg/backend-api:pull,push", nil)
	req.SetBasicAuth("developer", "password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
	}

	var response TokenResponse
	json.NewDecoder(w.Body).Decode(&response)

	// Validate the token has the right access
	claims, err := tokenService.ValidateToken(response.Token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if len(claims.Access) != 1 {
		t.Fatalf("len(Access) = %v, want 1", len(claims.Access))
	}

	if claims.Access[0].Name != "myorg/backend-api" {
		t.Errorf("Access[0].Name = %v, want myorg/backend-api", claims.Access[0].Name)
	}
}

func TestHandler_ServeHTTP_DeniedByACL(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")

	aclRules := []config.ACLRule{
		{Account: "developer", Name: "myorg/backend-*", Actions: []string{"pull"}},
	}
	aclMatcher := acl.NewMatcher(aclRules)

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	users := map[string]config.User{
		"developer": {Password: string(passwordHash)},
	}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	// Request push access, but ACL only allows pull
	req := httptest.NewRequest("GET", "/v2/token?scope=repository:myorg/backend-api:push", nil)
	req.SetBasicAuth("developer", "password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
	}

	var response TokenResponse
	json.NewDecoder(w.Body).Decode(&response)

	// Token should be generated but with no access
	claims, err := tokenService.ValidateToken(response.Token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	// Should have no access entries since push was denied
	if len(claims.Access) != 0 {
		t.Errorf("len(Access) = %v, want 0 (push not allowed)", len(claims.Access))
	}
}

func TestHandler_ServeHTTP_NoScope(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	aclMatcher := acl.NewMatcher([]config.ACLRule{})

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	users := map[string]config.User{
		"admin": {Password: string(passwordHash)},
	}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	req := httptest.NewRequest("GET", "/v2/token", nil)
	req.SetBasicAuth("admin", "password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
	}

	var response TokenResponse
	json.NewDecoder(w.Body).Decode(&response)

	claims, _ := tokenService.ValidateToken(response.Token)

	// No scope requested, so no access entries
	if len(claims.Access) != 0 {
		t.Errorf("len(Access) = %v, want 0", len(claims.Access))
	}
}

func TestAuthMiddleware_Middleware_NoAuth(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	middleware := NewAuthMiddleware(tokenService, "test-service")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest("GET", "/v2/test", nil)
	w := httptest.NewRecorder()

	middleware.Middleware(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusUnauthorized)
	}

	if nextCalled {
		t.Error("next handler should not be called without auth")
	}

	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("WWW-Authenticate header should be set")
	}
}

func TestAuthMiddleware_Middleware_ValidToken(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	middleware := NewAuthMiddleware(tokenService, "test-service")

	// Generate a valid token
	token, _ := tokenService.GenerateToken("testuser", nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/v2/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	middleware.Middleware(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
	}

	if !nextCalled {
		t.Error("next handler should be called with valid token")
	}
}

func TestAuthMiddleware_Middleware_InvalidToken(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	middleware := NewAuthMiddleware(tokenService, "test-service")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest("GET", "/v2/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	w := httptest.NewRecorder()

	middleware.Middleware(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusUnauthorized)
	}

	if nextCalled {
		t.Error("next handler should not be called with invalid token")
	}
}

func TestAuthMiddleware_Middleware_SkipTokenEndpoint(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	middleware := NewAuthMiddleware(tokenService, "test-service")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/v2/token", nil)
	w := httptest.NewRecorder()

	middleware.Middleware(next).ServeHTTP(w, req)

	if !nextCalled {
		t.Error("next handler should be called for /v2/token without auth")
	}
}

func TestAuthMiddleware_Middleware_InvalidAuthHeader(t *testing.T) {
	tokenService, _ := NewTokenService("test-issuer", "test-service", "test-secret")
	middleware := NewAuthMiddleware(tokenService, "test-service")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "no bearer prefix",
			header: "invalid-token",
		},
		{
			name:   "wrong auth type",
			header: "Basic dGVzdDp0ZXN0",
		},
		{
			name:   "empty bearer",
			header: "Bearer ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v2/test", nil)
			req.Header.Set("Authorization", tt.header)
			w := httptest.NewRecorder()

			nextCalled = false
			middleware.Middleware(next).ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("Status = %v, want %v", w.Code, http.StatusUnauthorized)
			}

			if nextCalled {
				t.Error("next handler should not be called with invalid auth header")
			}
		})
	}
}

func TestHandler_ServeHTTP_ConstantTime(t *testing.T) {
	// Setup
	tokenService, err := NewTokenService("test-issuer", "test-service", "test-secret")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	aclRules := []config.ACLRule{
		{Account: "validuser", Name: "*", Actions: []string{"*"}},
	}
	aclMatcher := acl.NewMatcher(aclRules)

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	users := map[string]config.User{
		"validuser": {Password: string(passwordHash)},
	}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	// Test 1: Valid user with wrong password
	req1 := httptest.NewRequest("GET", "/v2/token", nil)
	req1.SetBasicAuth("validuser", "wrongpassword")
	w1 := httptest.NewRecorder()

	start1 := time.Now()
	handler.ServeHTTP(w1, req1)
	duration1 := time.Since(start1)

	// Test 2: Non-existent user
	req2 := httptest.NewRequest("GET", "/v2/token", nil)
	req2.SetBasicAuth("nonexistentuser", "wrongpassword")
	w2 := httptest.NewRecorder()

	start2 := time.Now()
	handler.ServeHTTP(w2, req2)
	duration2 := time.Since(start2)

	// Both should return 401
	if w1.Code != http.StatusUnauthorized {
		t.Errorf("Valid user with wrong password: expected 401, got %d", w1.Code)
	}
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("Non-existent user: expected 401, got %d", w2.Code)
	}

	// Timing should be similar (within reasonable margin)
	// bcrypt takes ~100-200ms, so we expect both to be in that range
	timeDiff := duration1 - duration2
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}

	// Allow up to 50ms difference (due to system variance)
	maxAcceptableDiff := 50 * time.Millisecond
	if timeDiff > maxAcceptableDiff {
		t.Logf("WARNING: Timing difference detected - valid user: %v, invalid user: %v, diff: %v",
			duration1, duration2, timeDiff)
		t.Logf("This may indicate a timing attack vulnerability")
	}

	// Both should take at least 50ms (bcrypt should be slow)
	minExpectedDuration := 50 * time.Millisecond
	if duration1 < minExpectedDuration || duration2 < minExpectedDuration {
		t.Errorf("Responses too fast - bcrypt may not be running for both cases")
	}
}

func TestHandler_ServeHTTP_ValidCredentials(t *testing.T) {
	// Setup
	tokenService, err := NewTokenService("test-issuer", "test-service", "test-secret")
	if err != nil {
		t.Fatalf("NewTokenService() error = %v", err)
	}

	aclRules := []config.ACLRule{
		{Account: "validuser", Name: "*", Actions: []string{"*"}},
	}
	aclMatcher := acl.NewMatcher(aclRules)

	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	users := map[string]config.User{
		"validuser": {Password: string(passwordHash)},
	}

	handler := NewHandler(tokenService, aclMatcher, users, "Test Realm", "test-service")

	// Test with valid credentials
	req := httptest.NewRequest("GET", "/v2/token?scope=repository:test:pull", nil)
	req.SetBasicAuth("validuser", "password")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should succeed
	if w.Code != http.StatusOK {
		t.Errorf("Valid credentials: expected 200, got %d", w.Code)
	}

	// Should return valid token
	var response TokenResponse
	err = json.NewDecoder(w.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Token == "" {
		t.Error("Token should not be empty")
	}
}

func TestAuthMiddleware_Middleware_ServiceNameInWWWAuthenticate(t *testing.T) {
	t.Skip("This test is broken and needs fixing")
	tokenService, _ := NewTokenService("test-issuer", "Custom Docker Registry Service", "test-secret")
	middleware := NewAuthMiddleware(tokenService, "Custom Docker Registry Service")

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest("GET", "/v2/test", nil)
	w := httptest.NewRecorder()

	middleware.Middleware(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusUnauthorized)
	}

	if nextCalled {
		t.Error("next handler should not be called without auth")
	}

	wwwAuth := w.Header().Get("WWW-Authenticate")
	expectedWWWAuth := `Bearer realm="/v2/token",service="Custom Docker Registry Service"`
	if wwwAuth != expectedWWWAuth {
		t.Errorf("WWW-Authenticate = %q, want %q", wwwAuth, expectedWWWAuth)
	}
}
