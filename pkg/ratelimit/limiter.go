package ratelimit

import (
	"net/http"
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

// Middleware returns an HTTP middleware that enforces rate limiting
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := utils.GetClientIP(r)
		limiter := l.getVisitor(ip)

		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
