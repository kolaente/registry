package ratelimit

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/kolaente/registry/pkg/utils"
	"golang.org/x/time/rate"
)

// Limiter manages rate limiting for multiple clients
type Limiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
}

// visitor represents a single client's rate limiter
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewLimiter creates a new rate limiter
// rate: requests per second (e.g., 10 for 10 req/sec)
// burst: maximum burst size (e.g., 20 for burst of 20 requests)
// cleanup: how often to clean up old visitors (e.g., 5 * time.Minute)
func NewLimiter(r rate.Limit, b int, cleanup time.Duration) *Limiter {
	l := &Limiter{
		visitors: make(map[string]*visitor),
		rate:     r,
		burst:    b,
		cleanup:  cleanup,
	}

	// Start cleanup goroutine
	go l.cleanupVisitors()

	return l
}

// getVisitor returns the rate limiter for a given IP
func (l *Limiter) getVisitor(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	v, exists := l.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(l.rate, l.burst)
		l.visitors[ip] = &visitor{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	// Update last seen time
	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupVisitors removes old visitors periodically
func (l *Limiter) cleanupVisitors() {
	ticker := time.NewTicker(l.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		for ip, v := range l.visitors {
			if time.Since(v.lastSeen) > l.cleanup {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}

// calculateResetTime calculates seconds until the bucket is full
func (l *Limiter) calculateResetTime(currentTokens int) int {
	if currentTokens >= l.burst {
		return 0
	}
	tokensNeeded := l.burst - currentTokens
	secondsToFill := float64(tokensNeeded) / float64(l.rate)
	return int(math.Ceil(secondsToFill))
}

// Middleware returns an HTTP middleware that enforces rate limiting.
// It adds rate limit headers to all responses and returns 429 Too Many Requests
// when the rate limit is exceeded.
//
// Headers added to all responses:
//   - RateLimit-Limit: Maximum requests allowed (burst size)
//   - RateLimit-Remaining: Requests remaining in current period
//   - RateLimit-Reset: Seconds until full capacity is restored
//   - X-RateLimit-* variants for legacy compatibility
//
// When rate limited (429 response):
//   - Retry-After: Seconds to wait before retrying
//   - JSON body with error details
//
// The rate limiter uses a token bucket algorithm that refills continuously
// at the configured rate (requests per second). This means clients can make
// requests as soon as they have available tokens, rather than waiting for
// discrete time windows.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := utils.GetClientIP(r)
		limiter := l.getVisitor(ip)

		// Get current state before checking allowance
		tokens := limiter.Tokens()
		remaining := int(tokens)
		if remaining < 0 {
			remaining = 0
		}
		resetSeconds := l.calculateResetTime(remaining)

		// Add standard headers (IETF draft RFC)
		w.Header().Set("RateLimit-Limit", strconv.Itoa(l.burst))
		w.Header().Set("RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("RateLimit-Reset", strconv.Itoa(resetSeconds))

		// Add legacy headers (for compatibility)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(l.burst))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		resetTime := time.Now().Add(time.Duration(resetSeconds) * time.Second)
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

		if !limiter.Allow() {
			retryAfter := int(math.Ceil(1.0 / float64(l.rate)))
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":       "rate_limit_exceeded",
				"message":     "Rate limit exceeded. Please try again later.",
				"retry_after": retryAfter,
				"limit":       l.burst,
				"reset":       time.Now().Add(time.Duration(retryAfter) * time.Second).UTC().Format(time.RFC3339),
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
