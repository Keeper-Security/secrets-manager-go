// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
// Keeper Secrets Manager
// Copyright 2025 Keeper Security Inc.
// Contact: sm@keepersecurity.com

package oraclekv

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"os"
	"path/filepath"

	"github.com/keeper-security/secrets-manager-go/core"
	olog "github.com/keeper-security/secrets-manager-go/core/logger"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

type OracleConfig struct {
	VaultManagementEndpoint string
	VaultCryptoEndpoint     string
	Profile                 string
	ProfileConfigPath       string
}

type KeyConfig struct {
	KeyID        string
	KeyVersionID string
}

type oracleKeyVaultStorage struct {
	configFileLocation  string
	config              map[core.ConfigKey]interface{}
	lastSavedConfigHash string
	oracleKMSClient     *keymanagement.KmsCryptoClient
	oracleConfig        *OracleConfig
	keyConfig           *KeyConfig
	keyDetails          *keymanagement.GetKeyResponse
}

// Creates a new OracleKeyVaultStorage instance.
func NewOracleKeyVaultStorage(configFileLocation string, keyConfig *KeyConfig, oracleConfig *OracleConfig) *oracleKeyVaultStorage {
	if configFileLocation == "" {
		if envConfigFileLocation, ok := os.LookupEnv("KSM_CONFIG_FILE"); ok {
			configFileLocation = envConfigFileLocation
		} else {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	if oracleConfig == nil {
		olog.Error("OracleConfig is required")
		return nil
	}

	client, err := getOracleKMSClient(oracleConfig)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to create Oracle KMS crypto client: %v", err.Error()))
		return nil
	}

	if keyConfig == nil {
		olog.Error("KeyConfig is required")
		return nil
	}

	keyDetails, err := getKeyDetails(keyConfig, oracleConfig)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to get key details: %v", err.Error()))
		return nil
	}

	if keyDetails.KeyShape.Algorithm != keymanagement.KeyShapeAlgorithmAes && keyDetails.KeyShape.Algorithm != keymanagement.KeyShapeAlgorithmRsa {
		olog.Error(fmt.Sprintf("Unsupported key encryption algorithm: %v", keyDetails))
		return nil
	}

	oracleStorage := &oracleKeyVaultStorage{
		config:              make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash: "",
		configFileLocation:  configFileLocation,
		oracleKMSClient:     client,
		keyConfig:           keyConfig,
		oracleConfig:        oracleConfig,
		keyDetails:          keyDetails,
	}

	if err := oracleStorage.loadConfig(); err != nil {
		olog.Error(fmt.Sprintf("Failed to load config: %v", err.Error()))
		return nil
	}

	return oracleStorage
}

// Loads the decrypted configuration from the config file if encrypted config is present, else encrypts the config.
func (o *oracleKeyVaultStorage) loadConfig() error {
	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptError bool
	var decryptData []byte

	if err := o.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(o.configFileLocation)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to load config file %s: %s", o.configFileLocation, err.Error()))
		return fmt.Errorf("failed to load config file %s", o.configFileLocation)
	}

	if len(contents) == 0 {
		olog.Error(fmt.Sprintf("Empty config file %s", o.configFileLocation))
		contents = []byte("{}")
	}

	if err := json.Unmarshal(contents, &config); err == nil {
		o.config = config
		if err := o.saveConfig(config, false); err != nil {
			olog.Error(fmt.Sprintf("Failed to save config: %v", err.Error()))
			return err
		}

		configJson, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		o.lastSavedConfigHash = o.createHash(configJson)
	} else {
		jsonError = err
	}

	if jsonError != nil {

		if o.keyDetails.KeyShape.Algorithm == keymanagement.KeyShapeAlgorithmAes {
			decryptData, err = decryptSymmetric(o.oracleKMSClient, o.keyConfig, contents)
			if err != nil {
				decryptError = true
				olog.Error(fmt.Sprintf("Symmetric decryption failed: %s", err.Error()))
				return fmt.Errorf("failed to decrypt config file %w", err)
			}

		} else {
			decryptData, err = decryptAsymmetric(o.oracleKMSClient, o.keyConfig, contents)
			if err != nil {
				decryptError = true
				olog.Error(fmt.Sprintf("Asymmetric decryption failed: %s", err.Error()))
				return fmt.Errorf("failed to decrypt config file %w", err)
			}
		}

		if err := json.Unmarshal(decryptData, &config); err != nil {
			decryptError = true
			olog.Error(fmt.Sprintf("Failed to parse decrypted config: %s", err.Error()))
			return fmt.Errorf("failed to parse decrypted config file %w", err)
		}

		o.config = config
		o.lastSavedConfigHash = o.createHash(decryptData)
	}

	if jsonError != nil && decryptError {
		olog.Error(fmt.Sprintf("Config file is not a valid JSON file: %s", jsonError.Error()))
		return fmt.Errorf("%s may contain JSON format problems", o.configFileLocation)
	}

	return nil
}

// Saves the encrypted updated configuration to the config file and updates the hash of the config.
func (o *oracleKeyVaultStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}, force bool) error {
	configJson, err := json.Marshal(o.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configHash := o.createHash(configJson)
	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.Marshal(updatedConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		updatedConfigHash := o.createHash(updatedConfigJson)
		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			o.config = make(map[core.ConfigKey]interface{})
			for k, v := range updatedConfig {
				o.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if !force && configHash == o.lastSavedConfigHash {
		olog.Info("Skipped config JSON save. No changes detected.")
		return nil
	}

	if err := o.createConfigFileIfMissing(); err != nil {
		return err
	}

	if err := o.encryptConfig(configJson); err != nil {
		return err
	}

	o.lastSavedConfigHash = configHash
	return nil
}

// Creates the config file and encrypt if it is not already exist.
func (o *oracleKeyVaultStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(o.configFileLocation); !os.IsNotExist(err) {
		olog.Info(fmt.Sprintf("Config file already exists at: %s", o.configFileLocation))
		return nil
	}

	dir := filepath.Dir(o.configFileLocation)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := o.encryptConfig([]byte("{}")); err != nil {
		return err
	}

	olog.Info(fmt.Sprintf("Created config file at: %s", o.configFileLocation))
	return nil
}

// Creates a hash of the given configuration data.
func (g *oracleKeyVaultStorage) createHash(config []byte) string {
	olog.Debug("Creating hash of config")
	hash := md5.Sum(config)
	return hex.EncodeToString(hash[:])
}

// Encrypts the configuration data and writes it to the config file.
func (o *oracleKeyVaultStorage) encryptConfig(config []byte) error {
	if o.keyDetails.KeyShape.Algorithm == keymanagement.KeyShapeAlgorithmAes {
		olog.Debug("Encrypting config using symmetric key")
		encryptedData, err := encryptSymmetric(o.oracleKMSClient, o.keyConfig, config)
		if err != nil {
			olog.Error(fmt.Sprintf("Symmetric encryption failed: %s", err.Error()))
			return fmt.Errorf("failed to encrypt config: %w", err)
		}

		if err := os.WriteFile(o.configFileLocation, encryptedData, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}

	} else {
		olog.Debug("Encrypting config using asymmetric key")
		encryptedData, err := encryptAsymmetric(o.oracleKMSClient, o.keyConfig, config)
		if err != nil {
			olog.Error(fmt.Sprintf("Asymmetric encryption failed: %s", err.Error()))
			return fmt.Errorf("failed to encrypt config: %w", err)
		}

		if err := os.WriteFile(o.configFileLocation, encryptedData, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted config file: %w", err)
		}
	}

	return nil
}

func getOracleKMSClient(oracleConfig *OracleConfig) (*keymanagement.KmsCryptoClient, error) {
	var client keymanagement.KmsCryptoClient
	var err error

	if oracleConfig.Profile == "" && oracleConfig.ProfileConfigPath == "" {
		client, err = keymanagement.NewKmsCryptoClientWithConfigurationProvider(common.DefaultConfigProvider(), oracleConfig.VaultCryptoEndpoint)
		if err != nil {
			olog.Error(fmt.Sprintf("Failed to create Oracle KMS crypto client: %v", err.Error()))
			return nil, err
		}
	} else {
		client, err = keymanagement.NewKmsCryptoClientWithConfigurationProvider(common.CustomProfileConfigProvider(oracleConfig.ProfileConfigPath, oracleConfig.Profile), oracleConfig.VaultCryptoEndpoint)
		if err != nil {
			olog.Error(fmt.Sprintf("Failed to create Oracle KMS crypto client: %v", err.Error()))
			return nil, err
		}
	}

	return &client, nil
}

// Fetches the key details from Oracle
func getKeyDetails(keyConfig *KeyConfig, oracleConfig *OracleConfig) (*keymanagement.GetKeyResponse, error) {
	olog.Debug("Fetching key details from oracle")
	client, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(common.DefaultConfigProvider(), oracleConfig.VaultManagementEndpoint)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to create Oracle KMS management client: %v", err.Error()))
		return nil, err
	}

	req := keymanagement.GetKeyRequest{
		KeyId: common.String(keyConfig.KeyID),
	}

	resp, err := client.GetKey(context.Background(), req)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to get key details: %v", err.Error()))
		return nil, err
	}

	return &resp, nil
}

// Update and save the config according to new Key.
func (o *oracleKeyVaultStorage) ChangeKey(updatedKeyConfig *KeyConfig, updatedOracleConfig *OracleConfig) (bool, error) {
	oldKeyConfig := o.keyConfig
	oldOracleConfig := o.oracleConfig
	oldOracleKMSClient := o.oracleKMSClient
	oldKeyDetails := o.keyDetails

	if updatedOracleConfig != nil {
		updatedOracleConfig = o.oracleConfig
		newClient, err := getOracleKMSClient(updatedOracleConfig)
		if err != nil {
			olog.Error(fmt.Sprintf("Failed to create Oracle KMS crypto client: %v", err.Error()))
			return false, nil
		}
		o.oracleConfig = updatedOracleConfig
		o.oracleKMSClient = newClient
	}

	o.keyConfig = updatedKeyConfig
	keyDetails, err := getKeyDetails(updatedKeyConfig, o.oracleConfig)
	if err != nil {
		olog.Error(fmt.Sprintf("Failed to get key details: %v", err.Error()))
		return false, nil
	}

	o.keyDetails = keyDetails
	if err := o.saveConfig(make(map[core.ConfigKey]interface{}), true); err != nil {
		o.keyConfig = oldKeyConfig
		o.oracleConfig = oldOracleConfig
		o.oracleKMSClient = oldOracleKMSClient
		o.keyDetails = oldKeyDetails
		olog.Error(fmt.Sprintf("Failed to change the key to '%v' for config '%s': %v", updatedKeyConfig, o.configFileLocation, err.Error()))
		return false, fmt.Errorf("failed to change the key for %s: %w", o.configFileLocation, err)
	}

	return true, nil
}

// Decrypts the configuration data and returns it as a string. If autosave is true, the decrypted data is saved to the config file.
func (o *oracleKeyVaultStorage) DecryptConfig(autosave bool) (string, error) {
	var ciphertext []byte
	var plaintext []byte

	ciphertext, err := os.ReadFile(o.configFileLocation)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	if len(ciphertext) == 0 {
		olog.Error(fmt.Sprintf("Empty config file %s", o.configFileLocation))
		return "", nil
	}

	if o.keyDetails.KeyShape.Algorithm == keymanagement.KeyShapeAlgorithmAes {
		plaintext, err = decryptSymmetric(o.oracleKMSClient, o.keyConfig, ciphertext)
		if err != nil {
			olog.Error(fmt.Sprintf("Symmetric decryption failed: %s", err.Error()))
			return "", fmt.Errorf("failed to decrypt config file %w", err)
		}

	} else {
		plaintext, err = decryptAsymmetric(o.oracleKMSClient, o.keyConfig, ciphertext)
		if err != nil {
			olog.Error(fmt.Sprintf("Asymmetric decryption failed: %s", err.Error()))
			return "", fmt.Errorf("failed to decrypt config file %w", err)
		}
	}

	if len(plaintext) == 0 {
		olog.Error("Length of decrypted config is: %d", len(plaintext))
		return "", fmt.Errorf("empty config file")
	} else if autosave {
		if err := os.WriteFile(o.configFileLocation, plaintext, 0644); err != nil {
			olog.Error(fmt.Sprintf("failed to write decrypted config file %s: %v", o.configFileLocation, err))
			return "", fmt.Errorf("failed to write decrypted config file %s", o.configFileLocation)
		}
	}

	return string(plaintext), nil
}
