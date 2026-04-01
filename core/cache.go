package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const defautFilePath = "ksm_cache.bin"

// ICache defines the interface for caching encrypted KSM API responses.
// Implement this interface to provide a custom caching backend — for example,
// Redis, a relational database, or an in-memory store with TTL expiry —
// and register it with [SecretsManager.SetCache].
//
// The data passed to SaveCachedValue is already encrypted by the SDK;
// implementations do not need to add additional encryption.
//
// Example:
//
//	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: ...})
//	sm.SetCache(myCustomCache)
type ICache interface {
	// SaveCachedValue persists the encrypted payload. Called after each
	// successful API response.
	SaveCachedValue(data []byte) error

	// GetCachedValue returns the most recently saved payload. Return nil
	// (with a nil error) when the cache is empty or has expired; the SDK
	// will perform a fresh API request in that case.
	GetCachedValue() ([]byte, error)

	// Purge deletes the cached value. Called when the SDK detects the
	// cache is stale or on explicit invalidation.
	Purge() error
}

// File based cache
type fileCache struct {
	FilePath string
}

func (c *fileCache) SaveCachedValue(data []byte) error {
	if data == nil {
		data = []byte{}
	}
	return os.WriteFile(c.FilePath, data, 0600)
}

func (c *fileCache) GetCachedValue() ([]byte, error) {
	return os.ReadFile(c.FilePath)
}

func (c *fileCache) Purge() error {
	err := os.Remove(c.FilePath)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return err
}

func NewFileCache(filePath string) *fileCache {
	path := strings.TrimSpace(filePath)
	if path == "" {
		path = defautFilePath
	}

	// If the file path is not absolute
	// allow the directory that will contain the cache to be set with environment variables.
	// If KSM_CACHE_DIR is not set, the cache will be created in the current working directory.
	if !filepath.IsAbs(path) {
		if ksmCacheDir := strings.TrimSpace(os.Getenv("KSM_CACHE_DIR")); ksmCacheDir != "" {
			path = filepath.Join(ksmCacheDir, path)
		}
	}

	return &fileCache{FilePath: path}
}

// Memory based cache
type memoryCache struct {
	cache []byte
}

func (c *memoryCache) SaveCachedValue(data []byte) error {
	c.cache = []byte{} // always erase old value
	if len(data) > 0 {
		bytes := make([]byte, len(data))
		copy(bytes, data)
		c.cache = bytes
	}
	return nil
}

func (c *memoryCache) GetCachedValue() ([]byte, error) {
	return c.cache, nil
}

func (c *memoryCache) Purge() error {
	c.cache = []byte{}
	return nil
}

func NewMemoryCache() *memoryCache {
	return &memoryCache{cache: []byte{}}
}
