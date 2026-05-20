// -*- coding: utf-8 -*-

//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper Secrets Manager
// Copyright 2025 Keeper Security Inc.
// Contact: sm@keepersecurity.com

package awskv

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/keeper-security/secrets-manager-go/core"
	awslog "github.com/keeper-security/secrets-manager-go/core/logger"
)

type AWSConfig struct {
	ClientID     string
	ClientSecret string
	Region       string
}

type awsKeyVaultStorage struct {
	configFileLocation  string
	config              map[core.ConfigKey]interface{}
	lastSavedConfigHash string
	kmsClient           *kms.Client
	keyARN              string
	awsConfig           *AWSConfig
}

// Creates a new instance of AWSKeyVaultStorage.
func NewAWSKeyValueStorage(configFileLocation string, KeyARN string, awsSessionConfig *AWSConfig) *awsKeyVaultStorage {
	if configFileLocation == "" {
		if envConfigFileLocation, ok := os.LookupEnv("KSM_CONFIG_FILE"); ok {
			configFileLocation = envConfigFileLocation
		} else {
			configFileLocation = core.DEFAULT_CONFIG_PATH
		}
	}

	cfg, err := getConfig(awsSessionConfig)
	if err != nil {
		awslog.Error(fmt.Sprintf("Failed to create client secret credential: %v", err))
		return nil
	}

	if KeyARN == "" {
		awslog.Error("Key ARN is nil")
		return nil
	}

	// Generate a new AWS KMS client
	client := kms.NewFromConfig(*cfg)
	awsDetails := &awsKeyVaultStorage{
		configFileLocation:  configFileLocation,
		config:              make(map[core.ConfigKey]interface{}),
		lastSavedConfigHash: "",
		kmsClient:           client,
		keyARN:              KeyARN,
		awsConfig:           awsSessionConfig,
	}

	keyData, err := awsDetails.getKeyDetails()
	// If key is not type of encrypt/decrypt, client operations will fail.
	if err != nil && keyData.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		awslog.Error("Failed to create client secret credential: %v", err)
		return nil
	}

	err = awsDetails.loadConfig()
	if err != nil {
		awslog.Error(fmt.Sprintf("Failed to load config: %v", err))
		return nil
	}

	return awsDetails
}

// Loads the decrypted configuration from the config file if encrypted config is present, else encrypts the config.
func (a *awsKeyVaultStorage) loadConfig() error {
	var config map[core.ConfigKey]interface{}
	var jsonError error
	var decryptionError bool
	var decryptData []byte

	if err := a.createConfigFileIfMissing(); err != nil {
		return err
	}

	contents, err := os.ReadFile(a.configFileLocation)
	if err != nil {
		awslog.Error(fmt.Sprintf("Unable to load config file %s: %v", a.configFileLocation, err))
		return fmt.Errorf("failed to load config file %s", a.configFileLocation)
	}

	if len(contents) == 0 {
		awslog.Error(fmt.Sprintf("Empty config file %s", a.configFileLocation))
		contents = []byte("{}")
	}

	if err := json.Unmarshal(contents, &config); err == nil {
		a.config = config
		if err := a.saveConfig(config, false); err != nil {
			return err
		}

		configJson, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		a.lastSavedConfigHash = a.createHash(configJson)
	} else {
		jsonError = err
	}

	if jsonError != nil {
		keydata, err := a.getKeyDetails()
		if err != nil {
			return fmt.Errorf("failed to get key details: %w", err)
		}

		if keydata.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
			decryptData, err = decryptSymmetric(a.kmsClient, a.keyARN, contents)
			if err != nil {
				decryptionError = true
				awslog.Error(fmt.Sprintf("Unable to decrypt config file: %v", err))
				return fmt.Errorf("failed to decrypt config file %s", a.configFileLocation)
			}
		} else {
			decryptData, err = decryptAsymmetric(a.kmsClient, a.keyARN, contents)
			if err != nil {
				decryptionError = true
				awslog.Error(fmt.Sprintf("Unable to decrypt config file: %v", err))
				return fmt.Errorf("failed to decrypt config file %s", a.configFileLocation)
			}
		}

		if err := json.Unmarshal(decryptData, &config); err != nil {
			decryptionError = true
			awslog.Error(fmt.Sprintf("Unable to parse decrypted config file: %v", err))
			return fmt.Errorf("failed to parse decrypted config file %s", a.configFileLocation)
		}

		a.config = config
		a.lastSavedConfigHash = a.createHash(decryptData)
	}

	if jsonError != nil && decryptionError {
		awslog.Error(fmt.Sprintf("Config file %s may contain JSON format problems", a.configFileLocation))
		return fmt.Errorf("%s may contain JSON format problems", a.configFileLocation)
	}

	return nil
}

// Saves the encrypted updated configuration to the config file and updates the hash of the config.
func (a *awsKeyVaultStorage) saveConfig(updatedConfig map[core.ConfigKey]interface{}, force bool) error {
	configJson, err := json.Marshal(a.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configHash := a.createHash(configJson)
	if len(updatedConfig) > 0 {
		updatedConfigJson, err := json.Marshal(updatedConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		updatedConfigHash := a.createHash(updatedConfigJson)
		if updatedConfigHash != configHash {
			configHash = updatedConfigHash
			a.config = make(map[core.ConfigKey]interface{})
			for k, v := range updatedConfig {
				a.config[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if !force && configHash == a.lastSavedConfigHash {
		awslog.Info("Skipped config JSON save. No changes detected")
		return nil
	}

	if err := a.createConfigFileIfMissing(); err != nil {
		return err
	}

	if err := a.encryptConfig(configJson); err != nil {
		return err
	}

	a.lastSavedConfigHash = configHash
	return nil
}

// Creates the config file if does not exist and encrypts it.
func (a *awsKeyVaultStorage) createConfigFileIfMissing() error {
	if _, err := os.Stat(a.configFileLocation); !os.IsNotExist(err) {
		awslog.Debug(fmt.Sprintf("Config file already exists at: %s", a.configFileLocation))
		return nil
	}

	dir := filepath.Dir(a.configFileLocation)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := a.encryptConfig([]byte("{}")); err != nil {
		return err
	}

	awslog.Debug("Config file created at: %s", a.configFileLocation)
	return nil
}

// Retrieves the details of the KMS key.
func (a *awsKeyVaultStorage) getKeyDetails() (*kms.DescribeKeyOutput, error) {
	awslog.Debug("Getting key details")
	keyDetails, err := a.kmsClient.DescribeKey(context.Background(), &kms.DescribeKeyInput{
		KeyId: &a.keyARN,
	})

	if err != nil {
		awslog.Error(fmt.Sprintf("Failed to fetch key details from AWS: %v", err))
		return nil, fmt.Errorf("failed to fetch key details: %w", err)
	}

	return keyDetails, nil
}

// createHash creates an MD5 hash of the provided config data.
func (a *awsKeyVaultStorage) createHash(config []byte) string {
	awslog.Debug("Creating hash of config")
	hash := md5.Sum(config)
	return hex.EncodeToString(hash[:])
}

// Retrieves the AWS configuration.
// If the client ID, client secret, and region are provided, it returns the configuration with the provided values else it returns the default configuration.
func getConfig(awsSessionConfig *AWSConfig) (*aws.Config, error) {
	if awsSessionConfig.ClientID != "" && awsSessionConfig.ClientSecret != "" && awsSessionConfig.Region != "" {
		return &aws.Config{
			Credentials: credentials.NewStaticCredentialsProvider(awsSessionConfig.ClientID, awsSessionConfig.ClientSecret, ""),
			Region:      awsSessionConfig.Region,
		}, nil
	} else {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to load default config: %w", err)
		}
		return &cfg, nil
	}
}

// Encrypts the configuration data and writes it to the config file.
func (a *awsKeyVaultStorage) encryptConfig(config []byte) error {
	keydata, err := a.getKeyDetails()
	if err != nil {
		return err
	}

	var blob []byte
	if keydata.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
		awslog.Debug("Encrypting config with symmetric key")
		blob, err = encryptSymmetric(a.kmsClient, a.keyARN, config)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
	} else {
		awslog.Debug("Encrypting config with asymmetric key")
		blob, err = encryptAsymmetric(a.kmsClient, a.keyARN, config)
		if err != nil {
			return fmt.Errorf("failed to encrypt config: %w", err)
		}
	}

	if err := os.WriteFile(a.configFileLocation, blob, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", a.configFileLocation, err)
	}

	awslog.Debug(fmt.Sprintf("Config file created at: %s", a.configFileLocation))
	return nil
}

// Changes the KMS key used for encryption and decryption.
func (a *awsKeyVaultStorage) ChangeKey(updatedKeyARN string, updatedConfig *AWSConfig) (bool, error) {
	oldKeyARN := a.keyARN
	oldKMSClient := a.kmsClient
	if updatedConfig == nil {
		updatedConfig = a.awsConfig
	}

	config, err := getConfig(updatedConfig)
	if err != nil {
		return false, fmt.Errorf("failed to get config: %w", err)
	}

	client := kms.NewFromConfig(*config)
	a.kmsClient = client
	a.keyARN = updatedKeyARN
	if err := a.saveConfig(make(map[core.ConfigKey]interface{}), true); err != nil {
		a.kmsClient = oldKMSClient
		a.keyARN = oldKeyARN
		awslog.Error(fmt.Sprintf("Change key failed: %v", err))
		return false, fmt.Errorf("failed to change the key for %s: %w", a.configFileLocation, err)
	}

	return true, nil
}

func (a *awsKeyVaultStorage) DecryptConfig(autosave bool) (string, error) {
	var ciphertext []byte
	var plaintext []byte

	ciphertext, err := os.ReadFile(a.configFileLocation)
	if err != nil {
		return "", fmt.Errorf("failed to read config file: %w", err)
	}

	if len(ciphertext) == 0 {
		awslog.Error(fmt.Sprintf("Empty config file %s", a.configFileLocation))
		return "", nil
	}

	keydata, err := a.getKeyDetails()
	if err != nil {
		return "", fmt.Errorf("failed to get key details: %w", err)
	}

	if keydata.KeyMetadata.KeySpec == types.KeySpecSymmetricDefault {
		plaintext, err = decryptSymmetric(a.kmsClient, a.keyARN, ciphertext)
		awslog.Debug("Decrypting config with symmetric key")
		if err != nil {
			return "", fmt.Errorf("failed to decrypt config file %s", a.configFileLocation)
		}
	} else {
		plaintext, err = decryptAsymmetric(a.kmsClient, a.keyARN, ciphertext)
		awslog.Debug("Decrypting config with asymmetric key")
		if err != nil {
			return "", fmt.Errorf("failed to decrypt config file %s", a.configFileLocation)
		}
	}

	if len(plaintext) == 0 {
		awslog.Error("Length of decrypted config is: %d", len(plaintext))
		return "", fmt.Errorf("empty config file")
	} else if autosave {
		if err := os.WriteFile(a.configFileLocation, plaintext, 0644); err != nil {
			awslog.Error(fmt.Sprintf("failed to write decrypted config file %s: %v", a.configFileLocation, err))
			return "", fmt.Errorf("failed to write decrypted config file %s", a.configFileLocation)
		}
	}

	return string(plaintext), nil
}
