// Package main demonstrates the offline-fallback behavior of the ICache interface
// in the Keeper Secrets Manager Go SDK.
//
// The SDK cache is an offline resilience mechanism, not a request-rate limiter.
// The SDK always contacts the Keeper API on every call. After a successful 200
// response, it writes the encrypted payload to ICache.SaveCachedValue. When the
// API is unreachable — connection refused, DNS failure, TLS error, timeout, or
// a non-200 HTTP response — the SDK reads ICache.GetCachedValue and, if a prior
// payload exists, decrypts and returns those records instead of surfacing the
// error. A warning is logged when cached records are served.
//
// The TTL on TTLCache below controls how stale the offline copy is allowed to
// be, not how frequently the SDK contacts the API.
//
// To run this example, provide a valid ksm-config.json in the working directory
// (generated on first run with a one-time token), then:
//
//	go run main.go
package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	ksm "github.com/keeper-security/secrets-manager-go/core"
	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

// TTLCache is a thread-safe, in-memory ICache that discards cached values after
// a configured duration. Use this when you want the offline fallback to expire
// after a known staleness window — for example, 5 minutes means the SDK will
// never serve records older than 5 minutes when the API is unreachable.
type TTLCache struct {
	mu     sync.RWMutex
	data   []byte
	expiry time.Time
	ttl    time.Duration
}

// NewTTLCache creates a TTLCache with the given time-to-live duration.
func NewTTLCache(ttl time.Duration) *TTLCache {
	return &TTLCache{ttl: ttl}
}

// SaveCachedValue stores a defensive copy of the encrypted payload and resets
// the expiry timer. The SDK calls this after each successful API response.
func (c *TTLCache) SaveCachedValue(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	buf := make([]byte, len(data))
	copy(buf, data)
	c.data = buf
	c.expiry = time.Now().Add(c.ttl)
	return nil
}

// GetCachedValue returns the stored payload if it has not expired. Returning
// nil signals a cache miss; the SDK will surface the original API error.
func (c *TTLCache) GetCachedValue() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.data) == 0 || time.Now().After(c.expiry) {
		return nil, nil
	}
	return c.data, nil
}

// Purge clears the stored payload. Call this to force the next offline-fallback
// attempt to surface the real error rather than serve stale records.
func (c *TTLCache) Purge() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = nil
	c.expiry = time.Time{}
	return nil
}

func main() {
	klog.SetLogLevel(klog.InfoLevel)

	cache := NewTTLCache(5 * time.Minute)

	// ── Call 1: normal API request ───────────────────────────────────────────
	// The SDK contacts the Keeper API, receives a 200, and writes the encrypted
	// payload to cache.SaveCachedValue.
	klog.Info("Call 1 — normal API request; cache will be populated on success")
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{
		Config: ksm.NewFileKeyValueStorage("ksm-config.json"),
	})
	sm.SetCache(cache)

	secrets, err := sm.GetSecrets([]string{})
	if err != nil {
		klog.Error("call 1 failed: " + err.Error())
		os.Exit(1)
	}
	fmt.Printf("Call 1: retrieved %d secret(s) from the API\n", len(secrets))

	// ── Call 2: API unreachable, cache populated ─────────────────────────────
	// A new client is pointed at an invalid hostname to force a DNS failure.
	// The SDK cannot reach the API, consults the cache, finds the prior payload,
	// and returns the same records. A WARNING line is logged.
	klog.Info("Call 2 — API unreachable (bad hostname); expect cached records")
	smOffline := ksm.NewSecretsManager(&ksm.ClientOptions{
		Config:   ksm.NewFileKeyValueStorage("ksm-config.json"),
		Hostname: "keepersecurity.invalid", // guaranteed NXDOMAIN
	})
	smOffline.SetCache(cache)

	secrets, err = smOffline.GetSecrets([]string{})
	if err != nil {
		klog.Error("call 2 failed unexpectedly (cache should have served records): " + err.Error())
		os.Exit(1)
	}
	fmt.Printf("Call 2: retrieved %d secret(s) from cache (API was unreachable)\n", len(secrets))

	// ── Call 3: cache purged, API still unreachable ──────────────────────────
	// After Purge(), GetCachedValue returns nil. The SDK has no fallback and
	// surfaces the original network error.
	klog.Info("Call 3 — cache purged, API still unreachable; expect network error")
	if err := cache.Purge(); err != nil {
		klog.Error("purge failed: " + err.Error())
		os.Exit(1)
	}

	_, err = smOffline.GetSecrets([]string{})
	if err != nil {
		fmt.Printf("Call 3: got expected error (cache empty + API unreachable): %v\n", err)
	} else {
		klog.Error("call 3 should have returned an error but did not")
		os.Exit(1)
	}
}
