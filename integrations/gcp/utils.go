package gcpkv

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"hash/crc32"
	"io"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	glog "github.com/keeper-security/secrets-manager-go/core/logger"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	BLOB_HEADER = "\xff\xff"
)

// Encrypts the message using a symmetric key stored in Google Cloud KMS.
func encryptionSymmetric(ctx context.Context, gcpKMClient *kms.KeyManagementClient, keyResourceName string, message []byte) ([]byte, error) {
	glog.Debug("Encryption Symmetric")
	if keyResourceName == "" {
		glog.Error("keyResourceName is empty")
		return nil, fmt.Errorf("keyResourceName is empty")
	}

	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}

	text, err := gcpKMClient.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:            keyResourceName,
		Plaintext:       message,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32c(message))),
	})

	if err != nil {
		glog.Error(fmt.Sprintf("Symmetric Encryption failed: %v", err.Error()))
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}

	return text.Ciphertext, nil
}

// Decrypts the ciphertext using a symmetric key stored in Google Cloud KMS.
func decryptionSymmetric(ctx context.Context, gcpKMClient *kms.KeyManagementClient, keyResourceName string, cipherText []byte) ([]byte, error) {
	glog.Debug("Decryption Symmetric")
	if keyResourceName == "" {
		glog.Error("Empty keyResourceName")
		return nil, fmt.Errorf("keyResourceName is empty")
	}

	index := strings.Index(keyResourceName, "/cryptoKeyVersions/")
	if index != -1 {
		keyResourceName = keyResourceName[:index]
	}

	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}

	plainText, err := gcpKMClient.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:             keyResourceName,
		Ciphertext:       cipherText,
		CiphertextCrc32C: wrapperspb.Int64(int64(crc32c(cipherText))),
	})
	if err != nil {
		glog.Error(fmt.Sprintf("Symmetric Decryption failed: %v", err.Error()))
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return plainText.Plaintext, nil
}

// Encrypts the key using an asymmetric key stored in Google Cloud KMS.
func encryptionAsymmetricKey(ctx context.Context, gcpKMClient *kms.KeyManagementClient, keyResourceName string, key []byte) ([]byte, error) {
	glog.Debug("Encryption Asymmetric Key")
	response, err := gcpKMClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyResourceName,
	})
	if err != nil {
		glog.Error(fmt.Sprintf("Error while fetching public key: %v", err.Error()))
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key: no PEM data found")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not rsa")
	}

	keyVersion, err := gcpKMClient.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: keyResourceName,
	})
	if err != nil {
		glog.Error(fmt.Sprintf("Error while fetching key version: %v", err.Error()))
		return nil, fmt.Errorf("failed to get key version: %w", err)
	}

	hashAlg, ok := keyDetails[keyVersion.Algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported key algorithm: %v", keyVersion.Algorithm)
	}

	ciphertext, err := rsa.EncryptOAEP(hashAlg, rand.Reader, rsaKey, key, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa.EncryptOAEP: %w", err)
	}

	return ciphertext, nil
}

// Decrypts the ciphertext key using an asymmetric key stored in Google Cloud KMS.
func decryptAsymmetricKey(ctx context.Context, gcpKMClient *kms.KeyManagementClient, keyResourceName string, key []byte) ([]byte, error) {
	glog.Debug("Decryption Asymmetric Key")
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	ciphertextCRC32C := crc32c(key)

	req := &kmspb.AsymmetricDecryptRequest{
		Name:             keyResourceName,
		Ciphertext:       key,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	result, err := gcpKMClient.AsymmetricDecrypt(ctx, req)
	if err != nil {
		glog.Error(fmt.Sprintf("Asymmetric Decryption failed: %v", err.Error()))
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	if !result.VerifiedCiphertextCrc32C {
		return nil, fmt.Errorf("AsymmetricDecrypt: request corrupted in-transit")
	}

	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("AsymmetricDecrypt: response corrupted in-transit")
	}

	return result.Plaintext, nil
}

// Encrypts the message using an asymmetric key stored in Google Cloud KMS.
func encryptAsymmetric(ctx context.Context, gcpKMClient *kms.KeyManagementClient, keyResourceName string, message []byte) ([]byte, error) {
	glog.Debug("Encryption Asymmetric")
	var blob []byte
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
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

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, message, nil)
	tag := ciphertext[len(ciphertext)-aesGCM.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-aesGCM.Overhead()]

	encryptedKey, err := encryptionAsymmetricKey(ctx, gcpKMClient, keyResourceName, key)
	if err != nil {
		glog.Error(fmt.Sprintf("Encryption Asymmetric failed: %v", err.Error()))
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	blob = append([]byte{}, []byte(BLOB_HEADER)...)

	components := [][]byte{
		encryptedKey,
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

// Decrypts the given ciphertext using an asymmetric key stored in Google Cloud KMS.
func decryptAsymmetric(ctx context.Context, gcpKMClient *kms.KeyManagementClient, keyResourceName string, cipherText []byte) ([]byte, error) {
	glog.Debug("Decryption Asymmetric")
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

	decryptedKey, err := decryptAsymmetricKey(ctx, gcpKMClient, keyResourceName, components[0])
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(decryptedKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, components[1], append(components[3], components[2]...), nil)
	if err != nil {
		glog.Error(fmt.Sprintf("Data tampering detected or decryption failed: %v", err.Error()))
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return plaintext, nil
}

func uint32ToBytes(n uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n)
	return buf
}
