package core

import (
	"io/ioutil"
	"os"
	"strings"
)

const defautFilePath = "ksm_cache.bin"

type ICache interface {
	SaveCachedValue(data []byte) error
	GetCachedValue() ([]byte, error)
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
	return ioutil.WriteFile(c.FilePath, data, 0600)
}

func (c *fileCache) GetCachedValue() ([]byte, error) {
	return ioutil.ReadFile(c.FilePath)
}

func (c *fileCache) Purge() error {
	return os.Remove(c.FilePath)
}

func NewFileCache(filePath string) *fileCache {
	path := strings.TrimSpace(filePath)
	if path == "" {
		path = defautFilePath
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
