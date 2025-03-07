package azurekv

import (
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
	alog "github.com/keeper-security/secrets-manager-go/core/logger"
)

func (a *azureKeyValueStorage) ReadStorage() map[string]interface{} {
	if err := a.loadConfig(); err != nil {
		alog.Error(fmt.Sprintf("Failed to load config: %v", err))
		return nil
	}
	convertedConfig := make(map[string]interface{})
	for k, v := range a.config {
		convertedConfig[string(k)] = v
	}
	return convertedConfig
}

func (a *azureKeyValueStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := a.saveConfig(convertedConfig, false); err != nil {
		alog.Error(fmt.Sprintf("Failed to save config: %v", err))
	}
}

func (a *azureKeyValueStorage) Get(key core.ConfigKey) string {
	if val, ok := a.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""

}

func (a *azureKeyValueStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	a.config[key] = value
	convertedConfig := make(map[string]interface{})
	for k, v := range a.config {
		convertedConfig[string(k)] = v
	}

	a.SaveStorage(convertedConfig)
	return a.ReadStorage()
}

func (a *azureKeyValueStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := a.config[key]; found {
		delete(a.config, key)
		alog.Debug(fmt.Sprintf("Removed key: %s", string(key)))
		a.saveConfig(a.config, false)
	} else {
		alog.Warning(fmt.Sprintf("Key not found: %s", string(key)))
	}

	return a.ReadStorage()
}

func (a *azureKeyValueStorage) DeleteAll() map[string]interface{} {
	a.config = map[core.ConfigKey]interface{}{}
	a.saveConfig(a.config, false)
	return a.ReadStorage()
}

func (a *azureKeyValueStorage) IsEmpty() bool {
	return len(a.config) == 0
}

func (a *azureKeyValueStorage) Contains(key core.ConfigKey) bool {
	_, found := a.config[key]
	return found
}
