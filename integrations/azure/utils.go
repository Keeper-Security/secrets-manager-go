package azurekv

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/keeper-security/secrets-manager-go/integrations/azure/logger"
)

const (
	BLOB_HEADER = "\xff\xff"
)

// Wrap the AES key using the key provided by the Azure Key Vault.
func encryptBuffer(azureKvStorageCryptoClient *azkeys.Client, keyName string, keyVersion string, message []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, message, nil)
	tag := ciphertext[len(ciphertext)-gcm.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-gcm.Overhead()]
	parameters := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     key,
	}

	wrappedKeyResp, err := azureKvStorageCryptoClient.WrapKey(context.Background(), keyName, keyVersion, parameters, nil)
	if err != nil {
		logger.Errorf("Failed to wrap key: %v", err)
		return nil, fmt.Errorf("azure crypto client failed to wrap key: %w", err)
	}

	wrappedKey := wrappedKeyResp.Result
	blob := append([]byte{}, []byte(BLOB_HEADER)...)

	components := [][]byte{
		wrappedKey,
		nonce,
		tag,
		ciphertext,
	}

	// Iterate over the components and append the length and data
	for _, comp := range components {
		blob = append(blob, uint32ToBytes(uint32(len(comp)))...)
		blob = append(blob, comp...)
	}
	return blob, nil
}

func uint32ToBytes(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

// UnWrap the AES key using the key provided by the Azure Key Vault.
func decryptBuffer(azureKeyValueStorageCryptoClient *azkeys.Client, keyName string, keyVersion string, cipherText []byte) ([]byte, error) {
	if !bytes.HasPrefix(cipherText, []byte(BLOB_HEADER)) {
		return nil, fmt.Errorf("invalid BLOB_HEADER")
	}

	if len(cipherText) == 0 {
		return nil, fmt.Errorf("empty encoded cipher text")
	}

	cipherText = cipherText[len(BLOB_HEADER):]

	// Extract components
	components := make([][]byte, 4)
	for i := range components {
		compLen := binary.BigEndian.Uint32(cipherText[:4])
		cipherText = cipherText[4:]
		components[i] = cipherText[:compLen]
		cipherText = cipherText[compLen:]
	}

	parameters := azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP),
		Value:     components[0],
	}

	decryptedKey, err := azureKeyValueStorageCryptoClient.UnwrapKey(context.Background(), keyName, keyVersion, parameters, nil)
	if err != nil {
		logger.Errorf("Failed to unwrap key: %v", err)
		return nil, fmt.Errorf("azure crypto client failed to unwrap key: %w", err)
	}

	block, err := aes.NewCipher(decryptedKey.Result)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, components[1], append(components[3], components[2]...), nil)
	if err != nil {
		logger.Errorf("Data tampering detected or decryption failed: %v", err)
		return nil, err
	}

	return plaintext, nil
}
