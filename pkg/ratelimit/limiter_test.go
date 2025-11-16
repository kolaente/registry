package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kolaente/registry/pkg/utils"
	"golang.org/x/time/rate"
)

func TestRateLimiter_Allow(t *testing.T) {
	limiter := NewLimiter(rate.Limit(2), 5, 1*time.Minute) // 2 req/sec, burst 5

	// Test handler
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// First 5 requests should succeed (burst)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", w.Code)
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	limiter := NewLimiter(rate.Limit(1), 1, 1*time.Minute) // 1 req/sec, burst 1

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request from IP 1
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	// Request from IP 2
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.2:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	// Both should succeed
	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Errorf("Different IPs should not affect each other's rate limits")
	}
}

func TestGetIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := utils.GetClientIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("Expected 203.0.113.1, got %s", ip)
	}
}

func TestGetIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "203.0.113.2")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := utils.GetClientIP(req)
	if ip != "203.0.113.2" {
		t.Errorf("Expected 203.0.113.2, got %s", ip)
	}
}

func TestGetIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	ip := utils.GetClientIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("Expected 192.168.1.1, got %s", ip)
	}
}

// TestMiddleware_Headers_Success verifies rate limit headers on successful requests
func TestMiddleware_Headers_Success(t *testing.T) {
	limiter := NewLimiter(rate.Limit(10), 20, 1*time.Minute) // 10 req/sec, burst 20

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Verify status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Verify standard headers
	if limit := w.Header().Get("RateLimit-Limit"); limit != "20" {
		t.Errorf("Expected RateLimit-Limit: 20, got %s", limit)
	}
	if remaining := w.Header().Get("RateLimit-Remaining"); remaining == "" {
		t.Error("Expected RateLimit-Remaining header to be present")
	}
	if reset := w.Header().Get("RateLimit-Reset"); reset == "" {
		t.Error("Expected RateLimit-Reset header to be present")
	}

	// Verify legacy headers
	if limit := w.Header().Get("X-RateLimit-Limit"); limit != "20" {
		t.Errorf("Expected X-RateLimit-Limit: 20, got %s", limit)
	}
	if remaining := w.Header().Get("X-RateLimit-Remaining"); remaining == "" {
		t.Error("Expected X-RateLimit-Remaining header to be present")
	}
	if reset := w.Header().Get("X-RateLimit-Reset"); reset == "" {
		t.Error("Expected X-RateLimit-Reset header to be present")
	}
}

// TestMiddleware_Headers_RateLimited verifies headers and response on 429
func TestMiddleware_Headers_RateLimited(t *testing.T) {
	limiter := NewLimiter(rate.Limit(1), 2, 1*time.Minute) // 1 req/sec, burst 2

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust the burst
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Request %d should succeed, got %d", i+1, w.Code)
		}
	}

	// This should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.2:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Verify 429 status
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", w.Code)
	}

	// Verify Retry-After header
	retryAfter := w.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("Expected Retry-After header on 429 response")
	}

	// Verify Content-Type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type: application/json, got %s", contentType)
	}

	// Verify JSON response body
	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if body["error"] != "rate_limit_exceeded" {
		t.Errorf("Expected error: rate_limit_exceeded, got %v", body["error"])
	}
	if body["message"] == nil {
		t.Error("Expected message field in JSON response")
	}
	if body["retry_after"] == nil {
		t.Error("Expected retry_after field in JSON response")
	}
	if body["limit"] != float64(2) {
		t.Errorf("Expected limit: 2, got %v", body["limit"])
	}
	if body["reset"] == nil {
		t.Error("Expected reset field in JSON response")
	}
}

// TestRetryAfterCalculation tests the retry-after calculation
func TestRetryAfterCalculation(t *testing.T) {
	tests := []struct {
		name          string
		rate          rate.Limit
		burst         int
		expectedRetry int
	}{
		{"1 req/sec", rate.Limit(1), 5, 1},
		{"10 req/sec", rate.Limit(10), 20, 1},
		{"0.5 req/sec", rate.Limit(0.5), 5, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiter(tt.rate, tt.burst, 1*time.Minute)

			handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			// Exhaust the burst
			for i := 0; i < tt.burst; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.3:12345"
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
			}

			// Get rate limited
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.3:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			retryAfter := w.Header().Get("Retry-After")
			retryAfterInt, err := strconv.Atoi(retryAfter)
			if err != nil {
				t.Fatalf("Retry-After header is not a valid integer: %s", retryAfter)
			}

			if retryAfterInt != tt.expectedRetry {
				t.Errorf("Expected Retry-After: %d, got %d", tt.expectedRetry, retryAfterInt)
			}
		})
	}
}

// TestMiddleware_RemainingDecreases verifies remaining count decreases correctly
func TestMiddleware_RemainingDecreases(t *testing.T) {
	limiter := NewLimiter(rate.Limit(10), 5, 1*time.Minute) // 10 req/sec, burst 5

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	previousRemaining := 5
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.4:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		remaining := w.Header().Get("RateLimit-Remaining")
		remainingInt, err := strconv.Atoi(remaining)
		if err != nil {
			t.Fatalf("RateLimit-Remaining is not a valid integer: %s", remaining)
		}

		// Remaining should be less than or equal to previous
		if remainingInt > previousRemaining {
			t.Errorf("Request %d: Expected remaining <= %d, got %d", i+1, previousRemaining, remainingInt)
		}
		previousRemaining = remainingInt
	}
}

// TestMiddleware_Concurrent tests thread safety
func TestMiddleware_Concurrent(t *testing.T) {
	limiter := NewLimiter(rate.Limit(100), 200, 1*time.Minute)

	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var wg sync.WaitGroup
	numGoroutines := 50
	requestsPerGoroutine := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.5:12345"
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
			}
		}(i)
	}

	wg.Wait()
	// If we get here without a race condition, the test passes
}

// TestCalculateResetTime tests the reset time calculation
func TestCalculateResetTime(t *testing.T) {
	tests := []struct {
		name          string
		rate          rate.Limit
		burst         int
		currentTokens int
		expectedReset int
	}{
		{"Full bucket", rate.Limit(10), 20, 20, 0},
		{"Half bucket", rate.Limit(10), 20, 10, 1},
		{"Empty bucket", rate.Limit(10), 20, 0, 2},
		{"Low rate", rate.Limit(1), 10, 5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiter(tt.rate, tt.burst, 1*time.Minute)
			reset := limiter.calculateResetTime(tt.currentTokens)
			if reset != tt.expectedReset {
				t.Errorf("Expected reset: %d, got %d", tt.expectedReset, reset)
			}
		})
	}
}
