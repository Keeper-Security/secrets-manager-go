// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
// Keeper Secrets Manager
// Copyright 2025 Keeper Security Inc.
// Contact: sm@keepersecurity.com

package gcpkv

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"hash"
	"os"
	"path/filepath"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/keeper-security/secrets-manager-go/core"
	glog "github.com/keeper-security/secrets-manager-go/core/logger"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

type googleCloudKeyVaultStorage struct {
	configFileLocation     string
	config                 map[core.ConfigKey]interface{}
	lastSavedConfigHash    string
	keyResourceName        string
	keyDetails             *kmspb.CryptoKey
	credentialFileWithPath string
}

var keyDetails = map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]hash.Hash{
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256: sha256.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256: sha256.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256: sha256.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512: sha512.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1:   sha1.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1:   sha1.New(),
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1:   sha1.New(),
}

// Creates a new instance of GoogleCloudKeyVaultStorage with the provided configuration.
func NewGCPKeyVaultStorage(configFileLocation string, keyResourceName string, credentialFileWithPath string) *googleCloudKeyVaultStorage {
	ctx := context.Background()
	if configFileLocation == "" {
		if envConfigFileLocation, ok := os.LookupEnv("KSM_CONFIG_FILE"); ok {
			configFileLocation = envConfigFileLocation
		} else {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	if credentialFileWithPath == "" {
		glog.Error("Credential file location path is empty")
		return nil
	}

	if keyResourceName == "" {
		glog.Error("Key resource name is empty")
		return nil
	}

	keyDetails, err := getKeyDetails(ctx, credentialFileWithPath, keyResourceName)
	if err != nil {
		return nil
	}

	if keyDetails.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT && keyDetails.Purpose != kmspb.CryptoKey_ASYMMETRIC_DECRYPT && keyDetails.Purpose != kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT {
		glog.Error("The given key is not of type ENCRYPT_DECRYPT or ASYMMETRIC_DECRYPT or RAW_ENCRYPT_DECRYPT")
		return nil
	}

	gcpStorage := &googleCloudKeyVaultStorage{
		configFileLocation:     configFileLocation,
		config:                 make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash:    "",
		keyResourceName:        keyResourceName,
		keyDetails:             keyDetails,
		credentialFileWithPath: credentialFileWithPath,
	}

	if err := gcpStorage.loadConfig(); err != nil {
		glog.Error("Load config failed")
		return nil
	}
	return gcpStorage
}

// Loads the decrypted configuration from the config file if encrypted config is present, else encrypts the config.
func (g *googleCloudKeyVaultStorage) loadConfig() error {
	ctx := context.Background()
	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptionError bool
	var decryptData []byte

	client, err := getGCPKMSClient(g.credentialFileWithPath)
	if err != nil {
		return err
	}

	defer client.Close()

	if err := g.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(g.configFileLocation)
	if err != nil {
		glog.Error(fmt.Sprintf("Failed to load config file %s: %s", g.configFileLocation, err.Error()))
		return fmt.Errorf("failed to load config file %s", g.configFileLocation)
	}

	if len(contents) == 0 {
		glog.Error(fmt.Sprintf("empty config file %s", g.configFileLocation))
		contents = []byte("{}")
	}

	if err := json.Unmarshal(contents, &config); err == nil {
		g.config = config
		if err := g.saveConfig(config, false); err != nil {
			return err
		}

		configJson, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		g.lastSavedConfigHash = g.createHash(configJson)
	} else {
		jsonError = err
	}

	if jsonError != nil {
		if g.keyDetails.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
			decryptData, err = decryptionSymmetric(ctx, client, g.keyResourceName, contents)
			if err != nil {
				decryptionError = true
				glog.Error("Symmetric decryption failed: %s", err.Error())
				return fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
			}
		} else if g.keyDetails.Purpose == kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT {
			token, err := getOAuthToken(ctx, g.credentialFileWithPath)
			if err != nil {
				glog.Error("Failed to get OAuth token")
				return fmt.Errorf("failed to get OAuth token")
			}
			decryptData, err = decryptRawSymmteric(g.keyResourceName, contents, *token)
			if err != nil {
				decryptionError = true
				glog.Error(fmt.Sprintf("Raw symmetric decryption failed: %s", err.Error()))
				return fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
			}
		} else {
			decryptData, err = decryptAsymmetric(ctx, client, g.keyResourceName, contents)
			if err != nil {
				decryptionError = true
				glog.Error(fmt.Sprintf("Asymmetric decryption failed: %s", err.Error()))
				return fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
			}
		}

		if err := json.Unmarshal(decryptData, &config); err != nil {
			decryptionError = true
			glog.Error(fmt.Sprintf("Parsing of decrypt config failed: %s", err.Error()))
			return fmt.Errorf("failed to parse decrypted config file %s", g.configFileLocation)
		}

		g.config = config
		g.lastSavedConfigHash = g.createHash(decryptData)
	}

	if jsonError != nil && decryptionError {
		glog.Error(fmt.Sprintf("Config file is not a valid JSON file: %s", jsonError.Error()))
		return fmt.Errorf("%s may contain JSON format problems", g.configFileLocation)
	}

	return nil
}

// Saves the encrypted updated configuration to the config file and updates the hash of the config.
func (g *googleCloudKeyVaultStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}, force bool) error {
	ctx := context.Background()
	configJson, err := json.Marshal(g.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configHash := g.createHash(configJson)
	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.Marshal(updatedConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		updatedConfigHash := g.createHash(updatedConfigJson)
		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			g.config = make(map[core.ConfigKey]interface{})
			for k, v := range updatedConfig {
				g.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if !force && configHash == g.lastSavedConfigHash {
		glog.Info("Skipped config JSON save. No changes detected.")
		return nil
	}

	if err := g.createConfigFileIfMissing(); err != nil {
		return err
	}

	if err := g.encryptConfig(ctx, configJson); err != nil {
		return err
	}

	g.lastSavedConfigHash = configHash
	return nil
}

// Creates a hash of the given configuration data.
func (g *googleCloudKeyVaultStorage) createHash(config []byte) string {
	glog.Debug("Creating hash of config")
	hash := md5.Sum(config)
	return hex.EncodeToString(hash[:])
}

// Creates the config file if it does not already exist.
func (g *googleCloudKeyVaultStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(g.configFileLocation); !os.IsNotExist(err) {
		glog.Info("Config file already exists at: %s", g.configFileLocation)
		return nil
	}

	dir := filepath.Dir(g.configFileLocation)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := g.encryptConfig(context.Background(), []byte("{}")); err != nil {
		return err
	}

	glog.Info("Config file created at: %s", g.configFileLocation)
	return nil
}

// Retrieves the details of the specified key from Google Cloud KMS.
func getKeyDetails(ctx context.Context, credentialFileWithPath string, keyResourceName string) (*kmspb.CryptoKey, error) {
	glog.Info("Getting key details from GCP")
	client, err := getGCPKMSClient(credentialFileWithPath)
	if err != nil {
		return nil, err
	}

	defer client.Close()

	// Remove the cryptoKeyVersions/<version> from the keyResourceName
	index := strings.Index(keyResourceName, "/cryptoKeyVersions/")
	if index != -1 {
		keyResourceName = keyResourceName[:index]
	}

	req := &kmspb.GetCryptoKeyRequest{
		Name: keyResourceName,
	}

	// Fetch the key details from GCP
	resp, err := client.GetCryptoKey(ctx, req)
	if err != nil {
		glog.Error(fmt.Sprintf("Failed to fetch the key details from GCP: %v", err.Error()))
		return nil, fmt.Errorf("failed to get key details: %w", err)
	}

	return resp, nil
}

// Encrypts the configuration data and writes it to the config file.
func (g *googleCloudKeyVaultStorage) encryptConfig(ctx context.Context, config []byte) error {
	client, err := getGCPKMSClient(g.credentialFileWithPath)
	if err != nil {
		return err
	}

	defer client.Close()
	if g.keyDetails.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
		glog.Debug("Encrypting config using symmetric key")
		ciphertext, err := encryptionSymmetric(ctx, client, g.keyResourceName, config)
		if err != nil {
			return err
		}

		if err := os.WriteFile(g.configFileLocation, ciphertext, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	} else if g.keyDetails.Purpose == kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT {
		glog.Debug("Encrypting config using raw symmetric key")
		token, err := getOAuthToken(ctx, g.credentialFileWithPath)
		if err != nil {
			glog.Error("Failed to get OAuth token")
			return fmt.Errorf("failed to get OAuth token")
		}

		ciphertext, err := encryptRawSymmteric(g.keyResourceName, config, *token)
		if err != nil {
			return err
		}

		if err := os.WriteFile(g.configFileLocation, ciphertext, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	} else {
		glog.Debug("Encrypting config using asymmetric key")
		ciphertext, err := encryptAsymmetric(ctx, client, g.keyResourceName, config)
		if err != nil {
			return err
		}

		if err := os.WriteFile(g.configFileLocation, ciphertext, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	}

	return nil
}

func getGCPKMSClient(credentialFileWithPath string) (*kms.KeyManagementClient, error) {
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsFile(credentialFileWithPath))
	if err != nil {
		glog.Error(fmt.Sprintf("Failed to create GCP Key Management client: %v", err.Error()))
		return nil, fmt.Errorf("failed to create GCP Key Management client: %w", err)
	}

	return client, nil
}

func getOAuthToken(ctx context.Context, credentialFileWithPath string) (*string, error) {
	creds, err := os.ReadFile(credentialFileWithPath)
	if err != nil {
		glog.Error(fmt.Sprintf("Failed to read credentials file: %v", err.Error()))
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}
	config, err := google.JWTConfigFromJSON(creds, cloud_api_url)
	if err != nil {
		return nil, err
	}
	token, err := config.TokenSource(ctx).Token()
	if err != nil {
		return nil, err
	}

	return &token.AccessToken, nil
}

func (g *googleCloudKeyVaultStorage) ChangeKey(updatedKeyResourceName string, updatedCredentialFileWithPath string) (bool, error) {
	oldKeyResourceName := g.keyResourceName
	oldCredentialFileWithPath := g.credentialFileWithPath
	oldKeyDetails := g.keyDetails

	if updatedCredentialFileWithPath == "" {
		updatedCredentialFileWithPath = g.credentialFileWithPath
	}

	keyDetails, err := getKeyDetails(context.Background(), updatedCredentialFileWithPath, updatedKeyResourceName)
	if err != nil {
		glog.Error(fmt.Sprintf("Failed to get key details for key '%s': %v", updatedKeyResourceName, err))
		return false, err
	}

	g.keyDetails = keyDetails
	g.credentialFileWithPath = updatedCredentialFileWithPath
	g.keyResourceName = updatedKeyResourceName
	if err := g.saveConfig(make(map[core.ConfigKey]interface{}), true); err != nil {
		g.keyResourceName = oldKeyResourceName
		g.credentialFileWithPath = oldCredentialFileWithPath
		g.keyDetails = oldKeyDetails
		glog.Error(fmt.Sprintf("Failed to change the key to '%s' for config '%s': %v", updatedKeyResourceName, g.configFileLocation, err))
		return false, fmt.Errorf("failed to change the key for %s: %w", g.configFileLocation, err)
	}

	return true, nil
}

func (g *googleCloudKeyVaultStorage) DecryptConfig(autosave bool) (string, error) {
	var ciphertext []byte
	var plaintext []byte
	ctx := context.Background()

	ciphertext, err := os.ReadFile(g.configFileLocation)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	if len(ciphertext) == 0 {
		glog.Warning(fmt.Sprintf("empty config file %s", g.configFileLocation))
		return "", nil
	}

	gcpKeyManagementClient, err := getGCPKMSClient(g.credentialFileWithPath)
	if err != nil {
		return "", err
	}

	defer gcpKeyManagementClient.Close()

	if g.keyDetails.Purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
		plaintext, err = decryptionSymmetric(ctx, gcpKeyManagementClient, g.keyResourceName, ciphertext)
		if err != nil {
			glog.Error(fmt.Sprintf("Failed to decrypt config file: %s", err.Error()))
			return "", fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
		}
	} else if g.keyDetails.Purpose == kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT {
		token, err := getOAuthToken(ctx, g.credentialFileWithPath)
		if err != nil {
			glog.Error("Failed to get OAuth token")
			return "", fmt.Errorf("failed to get OAuth token")
		}
		plaintext, err = decryptRawSymmteric(g.keyResourceName, ciphertext, *token)
		if err != nil {
			glog.Error(fmt.Sprintf("Failed to decrypt config file: %s", err.Error()))
			return "", fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
		}
	} else {
		plaintext, err = decryptAsymmetric(ctx, gcpKeyManagementClient, g.keyResourceName, ciphertext)
		if err != nil {
			glog.Error(fmt.Sprintf("Failed to decrypt config file: %s", err.Error()))
			return "", fmt.Errorf("failed to decrypt config file %s", g.configFileLocation)
		}
	}

	if len(plaintext) == 0 {
		glog.Error("empty config file")
		return "", fmt.Errorf("empty config file")
	} else if autosave {
		if err := os.WriteFile(g.configFileLocation, plaintext, 0644); err != nil {
			glog.Error(fmt.Sprintf("failed to write decrypted config file %s: %v", g.configFileLocation, err))
			return "", fmt.Errorf("failed to write decrypted config file %s", g.configFileLocation)
		}
	}

	return string(plaintext), nil
}
