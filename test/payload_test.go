package test

import (
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestTransmissionKey(t *testing.T) {
	config := ksm.NewMemoryKeyValueStorage(`{ "clientKey": "1234", "hostname": "keepersecurity.com" }`)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config})
	for _, keyNum := range []string{"7", "8", "9", "10", "11", "12"} {
		if transmissionKey := sm.GenerateTransmissionKey(keyNum); transmissionKey != nil {
			if keyNum != transmissionKey.PublicKeyId {
				t.Error("public key id does not match the key num")
			}
			if len(transmissionKey.Key) != 32 {
				t.Error("the transmission key is not 32 bytes long")
			}
			if len(transmissionKey.EncryptedKey) != 125 {
				t.Error("the transmission encryptedKey is not 125 bytes long")
			}
		} else {
			t.Error("error generating the transmission key")
		}
	}
}
