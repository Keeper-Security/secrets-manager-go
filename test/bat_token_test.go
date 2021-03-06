package test

import (
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestDecryptionWithBatToken(t *testing.T) {
	secretKey, _ := ksm.GetRandomBytes(32)

	plaintext := "ABC123"
	plaintextBytes := []byte(plaintext)
	encrTextBytes, _ := ksm.EncryptAesGcm(plaintextBytes, secretKey)

	decryptedPlaintextBytes, _ := ksm.Decrypt(encrTextBytes, secretKey)
	decryptedPlaintext := string(decryptedPlaintextBytes[:])

	if plaintext != decryptedPlaintext {
		t.Errorf("Decryption with BAT token failed, got: %s, want: %s.", decryptedPlaintext, plaintext)
	}
}
