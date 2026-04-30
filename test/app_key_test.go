package test

import (
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

// TestJustBoundCorruptAppKeyReturnsError verifies that when the server returns
// a non-empty encryptedAppKey that cannot be decrypted (corrupt or tampered),
// GetSecrets returns an error instead of silently succeeding with empty records
// (KSM-916).
func TestJustBoundCorruptAppKeyReturnsError(t *testing.T) {
	defer ResetMockResponseQueue()

	// Config with clientKey but no appKey — the just-bound initial state.
	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig([]string{"appKey"}, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	// Response carries a non-empty encryptedAppKey that is random junk —
	// it will fail decryption with the clientKey.
	junk, _ := ksm.GetRandomBytes(48)
	res := NewMockResponse([]byte{}, 200, nil)
	res.EncryptedAppKey = ksm.BytesToBase64(junk)
	MockResponseQueue.AddMockResponse(res)

	_, err := sm.GetSecrets([]string{})
	if err == nil {
		t.Fatal("expected error when app key decryption fails, got nil")
	}
}
