package test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

// networkErrorTransport is an http.RoundTripper that always returns a connection-refused error.
type networkErrorTransport struct{}

func (networkErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connect: connection refused")
}

// memCache is a minimal ICache that stores one value in memory.
type memCache struct {
	data []byte
}

func (c *memCache) SaveCachedValue(data []byte) error {
	buf := make([]byte, len(data))
	copy(buf, data)
	c.data = buf
	return nil
}

func (c *memCache) GetCachedValue() ([]byte, error) {
	if len(c.data) == 0 {
		return nil, errors.New("cache empty")
	}
	return c.data, nil
}

func (c *memCache) Purge() error {
	c.data = nil
	return nil
}

func TestCacheFallbackOnNetworkError(t *testing.T) {
	// Call 1: normal 200 → populates the cache.
	// Call 2: network-level error → cache has a value → serve cached records, no error.
	// Call 3: cache purged + network-level error → error surfaces.
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	cfg := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: cfg}, Ctx)

	cache := &memCache{}
	sm.SetCache(cache)

	res := NewMockResponse([]byte{}, 200, nil)
	mockRecord := res.AddRecord("Cached Record", "login", "", nil, nil)
	mockRecord.Field("login", "", "", "", "cached-user")
	MockResponseQueue.AddMockResponse(res)

	// Call 1: normal API response.
	records, err := sm.GetSecrets(nil)
	if err != nil {
		t.Fatalf("call 1: unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("call 1: expected 1 record, got %d", len(records))
	}
	if len(cache.data) == 0 {
		t.Fatal("call 1: cache should be populated after successful API call")
	}

	// Switch to network-error transport — all subsequent PostFunction calls fail immediately.
	savedTransport := (*context).Transport
	(*context).Transport = networkErrorTransport{}
	defer func() { (*context).Transport = savedTransport }()

	// Call 2: network error + populated cache → should return cached records.
	records, err = sm.GetSecrets(nil)
	if err != nil {
		t.Fatalf("call 2: expected cached records, got error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("call 2: expected 1 cached record, got %d", len(records))
	}
	if records[0].Uid != mockRecord.Uid {
		t.Errorf("call 2: UID mismatch: got %q, want %q", records[0].Uid, mockRecord.Uid)
	}

	// Call 3: purge cache + network error → error should surface.
	if err := cache.Purge(); err != nil {
		t.Fatalf("purge failed: %v", err)
	}
	_, err = sm.GetSecrets(nil)
	if err == nil {
		t.Fatal("call 3: expected network error after cache purge, got nil")
	}
	if !strings.Contains(err.Error(), "error during POST request") {
		t.Errorf("call 3: unexpected error format: %v", err)
	}
}
