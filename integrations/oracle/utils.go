package oraclekv

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	olog "github.com/keeper-security/secrets-manager-go/core/logger"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

const (
	BLOB_HEADER = "\xff\xff"
)

func encryptSymmetric(client *keymanagement.KmsCryptoClient, keyConfig *KeyConfig, message []byte) ([]byte, error) {
	olog.Debug("Encrypting Symmetric data with Oracle KMS")
	req := keymanagement.EncryptRequest{
		EncryptDataDetails: keymanagement.EncryptDataDetails{
			EncryptionAlgorithm: keymanagement.EncryptDataDetailsEncryptionAlgorithmAes256Gcm,
			KeyId:               common.String(keyConfig.KeyID),
			KeyVersionId:        common.String(keyConfig.KeyVersionID),
			Plaintext:           common.String(base64.StdEncoding.EncodeToString(message)),
		},
	}

	resp, err := client.Encrypt(context.Background(), req)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to encrypt data: %v", err.Error()))
		return nil, err
	}

	return []byte(*resp.EncryptedData.Ciphertext), nil
}

func decryptSymmetric(client *keymanagement.KmsCryptoClient, keyConfig *KeyConfig, cipherText []byte) ([]byte, error) {
	olog.Debug("Decrypting Symmetric data with Oracle KMS")
	req := keymanagement.DecryptRequest{
		DecryptDataDetails: keymanagement.DecryptDataDetails{
			EncryptionAlgorithm: keymanagement.DecryptDataDetailsEncryptionAlgorithmAes256Gcm,
			KeyId:               common.String(keyConfig.KeyID),
			KeyVersionId:        common.String(keyConfig.KeyVersionID),
			Ciphertext:          common.String(string(cipherText)),
		},
	}

	resp, err := client.Decrypt(context.Background(), req)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to decrypt data: %v", err.Error()))
		return nil, err
	}

	decodedData, err := base64.StdEncoding.DecodeString(*resp.DecryptedData.Plaintext)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to decode data: %v", err.Error()))
		return nil, err
	}

	return decodedData, nil
}

func encryptAsymmetric(client *keymanagement.KmsCryptoClient, keyConfig *KeyConfig, message []byte) ([]byte, error) {
	olog.Debug("Encrypting Asymmetric data with Oracle KMS")
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

	req := keymanagement.EncryptRequest{EncryptDataDetails: keymanagement.EncryptDataDetails{
		EncryptionAlgorithm: keymanagement.EncryptDataDetailsEncryptionAlgorithmRsaOaepSha256,
		KeyId:               common.String(keyConfig.KeyID),
		KeyVersionId:        common.String(keyConfig.KeyVersionID),
		Plaintext:           common.String(base64.StdEncoding.EncodeToString(key)),
	}}

	enccryptData, err := client.Encrypt(context.Background(), req)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to encrypt key: %v", err.Error()))
		return nil, err
	}

	blob := append([]byte{}, []byte(BLOB_HEADER)...)
	components := [][]byte{
		[]byte(*enccryptData.EncryptedData.Ciphertext),
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

func decryptAsymmetric(client *keymanagement.KmsCryptoClient, keyConfig *KeyConfig, cipherText []byte) ([]byte, error) {
	olog.Debug("Decrypting Asymmetric data with Oracle KMS")
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

	req := keymanagement.DecryptRequest{
		DecryptDataDetails: keymanagement.DecryptDataDetails{
			EncryptionAlgorithm: keymanagement.DecryptDataDetailsEncryptionAlgorithmRsaOaepSha256,
			KeyId:               common.String(keyConfig.KeyID),
			KeyVersionId:        common.String(keyConfig.KeyVersionID),
			Ciphertext:          common.String(string(components[0])),
		},
	}

	decryptKey, err := client.Decrypt(context.Background(), req)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to decrypt key: %v", err.Error()))
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(*decryptKey.DecryptedData.Plaintext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, components[1], append(components[3], components[2]...), nil)
	if err != nil {
		olog.Error(fmt.Sprintf("Data tampering detected or decryption failed: %v", err.Error()))
		return nil, err
	}

	return plaintext, nil
}

func uint32ToBytes(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}
