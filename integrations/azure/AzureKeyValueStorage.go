// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|

// Keeper Secrets Manager
// Copyright 2025 Keeper Security Inc.
// Contact: sm@keepersecurity.com
package azurekv

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/keeper-security/secrets-manager-go/core"
	"github.com/keeper-security/secrets-manager-go/integrations/azure/logger"
)

type AzureConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	KeyURL       string
}

type azureKeyValueStorage struct {
	configFileLocation  string
	config              map[core.ConfigKey]interface{}
	lastSavedConfigHash string
	cryptoClient        *azkeys.Client
	keyName             string
	keyVersion          string
	azureConfig         *AzureConfig
}

// Creates a new instance of AzureKeyValueStorage.
func NewAzureKeyValueStorage(configFileLocation string, azSessionConfig *AzureConfig) *azureKeyValueStorage {
	if configFileLocation == "" {
		if envConfigFileLocation, ok := os.LookupEnv("KSM_CONFIG_FILE"); ok {
			configFileLocation = envConfigFileLocation
		} else {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	credential, err := fetchCredentials(azSessionConfig)
	if err != nil {
		logger.Errorf("Failed to fetch credentials: %v", err)
		return nil
	}

	baseURL, keyName, keyVersion, err := fetchKeyDetails(azSessionConfig.KeyURL)
	if err != nil {
		logger.Errorf("Failed to fetch key details from URL: %v", err)
		return nil
	}

	// Create a new Azure Key Vault client.
	client, err := azkeys.NewClient(baseURL, credential, nil)
	if err != nil {
		logger.Errorf("Failed to create Azure Key Vault client: %v", err)
		return nil
	}

	azureDetails := &azureKeyValueStorage{
		configFileLocation:  configFileLocation,
		config:              make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash: "",
		cryptoClient:        client,
		keyName:             keyName,
		keyVersion:          keyVersion,
		azureConfig:         azSessionConfig,
	}

	err = azureDetails.loadConfig()
	if err != nil {
		return nil
	}

	return azureDetails
}

// Loads the decrypted configuration from the config file if encrypted config is present, else encrypts the config.
func (s *azureKeyValueStorage) loadConfig() error {
	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptionError bool

	if err := s.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(s.configFileLocation)
	if err != nil {
		logger.Errorf("Failed to load config file %s: %s", s.configFileLocation, err.Error())
		return fmt.Errorf("failed to load config file %s", s.configFileLocation)
	}

	if len(contents) == 0 {
		logger.Errorf("Config file is empty %s", s.configFileLocation)
		contents = []byte("{}")
	}

	if err := json.Unmarshal(contents, &config); err == nil {
		s.config = config
		if err := s.saveConfig(config, false); err != nil {
			return err
		}

		configJson, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		s.lastSavedConfigHash = s.createHash(configJson)
	} else {
		jsonError = err
	}

	if jsonError != nil {
		configJson, err := decryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, contents)
		if err != nil {
			decryptionError = true
			logger.Errorf("Failed to decrypt config file: %s", err.Error())
			return fmt.Errorf("failed to decrypt config file %s", s.configFileLocation)
		}

		if err := json.Unmarshal(configJson, &config); err != nil {
			decryptionError = true
			logger.Errorf("Failed to parse decrypted config file: %s", err.Error())
			return fmt.Errorf("failed to parse decrypted config file %s", s.configFileLocation)
		}

		s.config = config
		configJsonBytes, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		s.lastSavedConfigHash = s.createHash(configJsonBytes)
	}

	if jsonError != nil && decryptionError {
		logger.Errorf("Config file is not a valid JSON file: %s", jsonError.Error())
		return fmt.Errorf("%s may contain JSON format problems", s.configFileLocation)
	}

	return nil
}

// Saves the encrypted updated configuration to the config file and updates the hash of the config.
func (s *azureKeyValueStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}, force bool) error {
	config := s.config
	if config == nil {
		config = make(map[core.ConfigKey]interface{})
	}

	configJson, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal current config: %w", err)
	}
	configHash := s.createHash(configJson)

	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.Marshal(updatedConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		updatedConfigHash := s.createHash(updatedConfigJson)
		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			s.config = make(map[core.ConfigKey]interface{})
			for k, v := range updatedConfig {
				s.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if !force && configHash == s.lastSavedConfigHash {
		logger.Info("Skipped config JSON save. No changes detected.")
		return nil
	}

	if err := s.createConfigFileIfMissing(); err != nil {
		return err
	}

	if err := s.encryptConfig(configJson); err != nil {
		return err
	}

	s.lastSavedConfigHash = configHash
	return nil
}

// Creates the config file if does not exist and encrypts it.
func (s *azureKeyValueStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(s.configFileLocation); !os.IsNotExist(err) {
		logger.Infof("Config file already exists at: %s", s.configFileLocation)
		return nil
	}

	dir := filepath.Dir(s.configFileLocation)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := s.encryptConfig([]byte("{}")); err != nil {
		return err
	}

	logger.Infof("Config file created at: %s", s.configFileLocation)
	return nil
}

// creates an MD5 hash of the provided config data.
func (s *azureKeyValueStorage) createHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func fetchCredentials(azSessionConfig *AzureConfig) (azcore.TokenCredential, error) {
	var secretCredentials azcore.TokenCredential
	var err error
	if azSessionConfig != nil && azSessionConfig.TenantID != "" && azSessionConfig.ClientID != "" && azSessionConfig.ClientSecret != "" {
		secretCredentials, err = azidentity.NewClientSecretCredential(azSessionConfig.TenantID, azSessionConfig.ClientID, azSessionConfig.ClientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create client secret credential: %w", err)
		}
	} else {
		secretCredentials, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create default Azure credential: %w", err)
		}
	}
	return secretCredentials, nil
}

func (s *azureKeyValueStorage) encryptConfig(config []byte) error {
	var blob []byte
	var err error

	if config == nil {
		blob, err = encryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, []byte("{}"))
		if err != nil {
			return fmt.Errorf("failed to encrypt empty configuration: %w", err)
		}
	} else {
		blob, err = encryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, config)
		if err != nil {
			return fmt.Errorf("failed to encrypt configuration: %w", err)
		}
	}

	if err := os.WriteFile(s.configFileLocation, blob, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", s.configFileLocation, err)
	}
	return nil
}

func fetchKeyDetails(keyURL string) (string, string, string, error) {
	if keyURL == "" {
		return "", "", "", fmt.Errorf("key URL is empty")
	}

	parsedURL, err := url.Parse(keyURL)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse key URL: %v", err)
	}
	pathSegments := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
	if len(pathSegments) < 3 {
		return "", "", "", fmt.Errorf("invalid key URL format")
	}
	vaultURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	keyName := pathSegments[1]
	keyVersion := pathSegments[2]
	return vaultURL, keyName, keyVersion, nil
}

// Changes the key used to encrypt/decrypt the configuration.
func (s *azureKeyValueStorage) ChangeKey(newKeyURL string) (bool, error) {
	oldState := struct {
		vaultURL, keyName, keyVersion string
		cryptoClient                  *azkeys.Client
	}{
		s.azureConfig.KeyURL, s.keyName, s.keyVersion, s.cryptoClient,
	}

	// Extract the key details like vaultURL, keyname and keyversion from the new key URL `https://<vault-name>.vault.azure.net/keys/<key-name>/<version>`
	vaultURL, keyName, keyVersion, err := fetchKeyDetails(newKeyURL)
	if err != nil {
		logger.Errorf("Failed to extract key details from URL '%s': %v", newKeyURL, err)
		return false, fmt.Errorf("failed to extract key details from URL '%s': %w", newKeyURL, err)
	}

	s.azureConfig.KeyURL = newKeyURL
	s.keyName = keyName
	s.keyVersion = keyVersion

	cred, err := fetchCredentials(s.azureConfig)
	if err != nil {
		return false, err
	}

	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	s.cryptoClient = client
	if err := s.saveConfig(s.config, true); err != nil {
		s.azureConfig.KeyURL = oldState.vaultURL
		s.keyName = oldState.keyName
		s.keyVersion = oldState.keyVersion
		s.cryptoClient = oldState.cryptoClient
		logger.Errorf("Failed to change the key to '%s' for config '%s': %v", newKeyURL, s.configFileLocation, err)
		return false, fmt.Errorf("failed to change the key for %s: %w", s.configFileLocation, err)
	}

	return true, nil
}

func (s *azureKeyValueStorage) DecryptConfig(autosave bool) (string, error) {
	var ciphertext []byte
	var plaintext []byte
	ciphertext, err := os.ReadFile(s.configFileLocation)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	if len(ciphertext) == 0 {
		logger.Warnf("empty config file %s", s.configFileLocation)
		return "", nil
	}

	plaintext, err = decryptBuffer(s.cryptoClient, s.keyName, s.keyVersion, ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt config file: %w", err)
	}

	if len(plaintext) == 0 {
		logger.Error("empty config file")
		return "", fmt.Errorf("empty config file")
	} else if autosave {
		if err := os.WriteFile(s.configFileLocation, plaintext, 0644); err != nil {
			logger.Error(fmt.Sprintf("failed to write decrypted config file %s: %v", s.configFileLocation, err))
			return "", fmt.Errorf("failed to write decrypted config file %s", s.configFileLocation)
		}
	}

	return string(plaintext), nil
}
