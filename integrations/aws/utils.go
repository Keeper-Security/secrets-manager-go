package awskv

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	awslog "github.com/keeper-security/secrets-manager-go/core/logger"
)

const (
	BLOB_HEADER = "\xff\xff"
)

// Encrypts the message using a symmetric key stored in AWS KMS.
func encryptSymmetric(client *kms.Client, keyId string, message []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is empty")
	}

	if len(message) == 0 {
		return nil, fmt.Errorf("message is empty")
	}

	cipherText, err := client.Encrypt(context.Background(), &kms.EncryptInput{
		KeyId:               &keyId,
		Plaintext:           message,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		awslog.Error("Symmetric Encryption failed: %v", err)
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}

	return cipherText.CiphertextBlob, nil
}

// Decrypts the given ciphertext using a symmetric key stored in AWS KMS.
func decryptSymmetric(client *kms.Client, keyId string, cipherText []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is empty")
	}

	if len(cipherText) == 0 {
		return nil, fmt.Errorf("cipherText is empty")
	}

	plainText, err := client.Decrypt(context.Background(), &kms.DecryptInput{
		KeyId:          &keyId,
		CiphertextBlob: cipherText,
	})
	if err != nil {
		awslog.Error(fmt.Sprintf("Symmetric Decryption failed: %v", err))
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return plainText.Plaintext, nil
}

// Encrypts the given message using an asymmetric key stored in AWS KMS.
func encryptAsymmetric(client *kms.Client, keyId string, message []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is required")
	}

	symmetricKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, symmetricKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, message, nil)
	tag := ciphertext[len(ciphertext)-aesGCM.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-aesGCM.Overhead()]

	// Encrypt the symmetric key using AWS KMS
	asymmetricKey, err := client.Encrypt(context.Background(), &kms.EncryptInput{
		KeyId:               &keyId,
		Plaintext:           symmetricKey,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		awslog.Error(fmt.Sprintf("Asymmetric encryption failed: %v", err))
		return nil, fmt.Errorf("failed to encrypt symmetric key: %v", err)
	}

	blob := append([]byte{}, []byte(BLOB_HEADER)...)

	components := [][]byte{
		asymmetricKey.CiphertextBlob,
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

// uint32ToBytes converts a uint32 to a byte slice.
func uint32ToBytes(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

// Decrypts the given ciphertext using an asymmetric key stored in AWS KMS.
func decryptAsymmetric(client *kms.Client, keyId string, cipherText []byte) ([]byte, error) {
	if keyId == "" {
		return nil, fmt.Errorf("keyId is empty")
	}

	if !bytes.HasPrefix(cipherText, []byte(BLOB_HEADER)) {
		return nil, fmt.Errorf("invalid BLOB_HEADER")
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

	// Decrypt the symmetric key using AWS KMS
	decryptedKey, err := client.Decrypt(context.Background(), &kms.DecryptInput{
		KeyId:               &keyId,
		CiphertextBlob:      components[0], // key
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		awslog.Error(fmt.Sprintf("Asymmetric decryption failed: %v", err))
		return nil, fmt.Errorf("failed to decrypt symmetric key: %w", err)
	}

	block, err := aes.NewCipher(decryptedKey.Plaintext)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, components[1], append(components[3], components[2]...), nil)
	if err != nil {
		awslog.Error(fmt.Sprintf("Data tampering detected or decryption failed: %v", err))
		return nil, err
	}

	return plaintext, nil
}
