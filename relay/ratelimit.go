package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	limits   map[string]*clientBucket
	rate     float64       // tokens per second
	burst    int           // max tokens
	cleanInt time.Duration // cleanup interval
}

type clientBucket struct {
	tokens    float64
	lastCheck time.Time
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		limits:   make(map[string]*clientBucket),
		rate:     rate,
		burst:    burst,
		cleanInt: 5 * time.Minute,
	}

	go rl.cleanupRoutine()
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.limits[ip]
	if !exists {
		rl.limits[ip] = &clientBucket{
			tokens:    float64(rl.burst) - 1,
			lastCheck: now,
		}
		return true
	}

	elapsed := now.Sub(bucket.lastCheck).Seconds()
	bucket.lastCheck = now
	bucket.tokens += elapsed * rl.rate
	if bucket.tokens > float64(rl.burst) {
		bucket.tokens = float64(rl.burst)
	}

	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	return false
}

func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.cleanInt)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, bucket := range rl.limits {
			if now.Sub(bucket.lastCheck) > 10*time.Minute {
				delete(rl.limits, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func getClientIP(r *http.Request) string {
	xfwd := r.Header.Get("X-Forwarded-For")
	if xfwd != "" {
		parts := strings.Split(xfwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
