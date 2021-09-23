package test

import (
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestPrepareContext(t *testing.T) {
	config := ksm.NewMemoryKeyValueStorage()
	config.Set(ksm.KEY_CLIENT_KEY, "MY CLIENT KEY")
	config.Set(ksm.KEY_APP_KEY, "MY APP KEY")

	// Pass in the config
	sm := ksm.NewSecretsManagerFromConfig(config)

	// There should be no app key
	if sm.Config.Get(ksm.KEY_APP_KEY) != "" {
		t.Error("found the app key")
	}

	if context := sm.PrepareContext(); context != nil {
		if len(context.TransmissionKey.Key) < 1 {
			t.Error("did not find a transmission key")
		}
		if len(context.ClientId) < 1 {
			t.Error("did not find a client id")
		}
	}
}
