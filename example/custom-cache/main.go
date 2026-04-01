// Package main demonstrates how to implement a custom ICache for the
// Keeper Secrets Manager Go SDK.
//
// This example implements a thread-safe in-memory cache with a configurable
// TTL (time-to-live). When the cached value expires, GetCachedValue returns
// nil so the SDK performs a fresh API request and repopulates the cache.
//
// To run this example, first provide a valid ksm-config.json in the working
// directory (created on first run using a one-time access token), then:
//
//	go run main.go
package main

import (
	"fmt"
	"sync"
	"time"

	ksm "github.com/keeper-security/secrets-manager-go/core"
	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

// TTLCache is a thread-safe, in-memory ICache implementation that discards
// cached values after a configured duration. This is useful for applications
// that need to limit API call frequency while ensuring the cache does not
// serve stale data indefinitely.
type TTLCache struct {
	mu     sync.RWMutex
	data   []byte
	expiry time.Time
	ttl    time.Duration
}

// NewTTLCache creates a TTLCache with the given time-to-live duration.
// After ttl elapses, GetCachedValue returns nil and the SDK re-fetches
// from the Keeper API.
func NewTTLCache(ttl time.Duration) *TTLCache {
	return &TTLCache{ttl: ttl}
}

// SaveCachedValue stores a defensive copy of the encrypted payload and
// resets the expiry timer. The SDK calls this after each successful API
// response — implementations must not modify the slice in place.
func (c *TTLCache) SaveCachedValue(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store a copy so the SDK can safely reuse its original buffer.
	buf := make([]byte, len(data))
	copy(buf, data)
	c.data = buf
	c.expiry = time.Now().Add(c.ttl)
	return nil
}

// GetCachedValue returns the stored payload if it has not expired.
// Returning nil (with a nil error) signals a cache miss: the SDK will
// perform a fresh API request and call SaveCachedValue with the result.
func (c *TTLCache) GetCachedValue() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.data) == 0 || time.Now().After(c.expiry) {
		return nil, nil // cache miss or expired
	}
	return c.data, nil
}

// Purge clears the cached value and resets the expiry. The SDK calls this
// when it detects the cache is stale or on explicit invalidation.
func (c *TTLCache) Purge() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = nil
	c.expiry = time.Time{}
	return nil
}

func main() {
	klog.SetLogLevel(klog.InfoLevel)

	// Initialize the Secrets Manager client.
	// One-time tokens can only be used once. After the first run, use only Config:
	//   sm := ksm.NewSecretsManager(&ksm.ClientOptions{
	//       Token:  "US:ONE_TIME_TOKEN_BASE64",
	//       Config: ksm.NewFileKeyValueStorage("ksm-config.json"),
	//   })
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{
		Config: ksm.NewFileKeyValueStorage("ksm-config.json"),
	})

	// Attach the custom TTL cache. The SDK will call SaveCachedValue after
	// each API response and GetCachedValue at the start of each request.
	// Adjust the TTL to balance freshness against API call frequency.
	sm.SetCache(NewTTLCache(5 * time.Minute))

	// First call — cache is empty, SDK fetches from Keeper API.
	klog.Info("First GetSecrets call (cache miss expected)")
	secrets, err := sm.GetSecrets([]string{})
	if err != nil {
		klog.Error("error retrieving secrets: " + err.Error())
		return
	}
	fmt.Printf("Retrieved %d secret(s)\n", len(secrets))

	// Second call within the TTL window — served from cache, no API request.
	klog.Info("Second GetSecrets call (cache hit expected within TTL)")
	secrets, err = sm.GetSecrets([]string{})
	if err != nil {
		klog.Error("error retrieving secrets: " + err.Error())
		return
	}
	fmt.Printf("Retrieved %d secret(s) (from cache)\n", len(secrets))
}
