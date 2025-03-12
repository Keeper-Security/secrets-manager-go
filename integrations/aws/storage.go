package awskv

import (
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
	awslog "github.com/keeper-security/secrets-manager-go/core/logger"
)

func (a *awsKeyVaultStorage) ReadStorage() map[string]interface{} {
	if err := a.loadConfig(); err != nil {
		awslog.Error(fmt.Sprintf("Failed to load config: %v", err))
		return nil
	}

	convertedConfig := make(map[string]interface{})
	for k, v := range a.config {
		convertedConfig[string(k)] = v
	}

	return convertedConfig
}

func (a *awsKeyVaultStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := a.saveConfig(convertedConfig, false); err != nil {
		awslog.Error(fmt.Sprintf("Failed to save config: %v", err))
	}
}

func (a *awsKeyVaultStorage) Get(key core.ConfigKey) string {
	if val, ok := a.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}

	return ""

}

func (a *awsKeyVaultStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	a.config[key] = value
	convertedConfig := make(map[string]interface{})
	for k, v := range a.config {
		convertedConfig[string(k)] = v
	}

	a.SaveStorage(convertedConfig)
	return a.ReadStorage()
}

func (a *awsKeyVaultStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := a.config[key]; found {
		delete(a.config, key)
		awslog.Debug(fmt.Sprintf("Deleted key '%s' from config", string(key)))
		a.saveConfig(a.config, false)
	} else {
		awslog.Error(fmt.Sprintf("Key '%s' not found in config", string(key)))
	}

	return a.ReadStorage()
}

func (a *awsKeyVaultStorage) DeleteAll() map[string]interface{} {
	a.config = map[core.ConfigKey]interface{}{}
	a.saveConfig(a.config, false)
	return a.ReadStorage()
}

func (a *awsKeyVaultStorage) IsEmpty() bool {
	return len(a.config) == 0
}

func (a *awsKeyVaultStorage) Contains(key core.ConfigKey) bool {
	_, found := a.config[key]
	return found
}
