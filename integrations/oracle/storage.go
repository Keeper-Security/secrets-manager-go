package oraclekv

import (
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
	olog "github.com/keeper-security/secrets-manager-go/core/logger"
)

func (o *oracleKeyVaultStorage) ReadStorage() map[string]interface{} {
	if err := o.loadConfig(); err != nil {
		olog.Error(fmt.Sprintf("Failed to load config: %v", err))
		return nil
	}

	convertedConfig := make(map[string]interface{})
	for k, v := range o.config {
		convertedConfig[string(k)] = v
	}

	return convertedConfig
}

func (o *oracleKeyVaultStorage) SaveStorage(updatedConfig map[string]interface{}) {
	convertedConfig := make(map[core.ConfigKey]interface{})
	for k, v := range updatedConfig {
		if strVal, ok := v.(string); ok {
			convertedConfig[core.ConfigKey(k)] = strVal
		}
	}

	if err := o.saveConfig(convertedConfig, false); err != nil {
		olog.Error(fmt.Sprintf("Failed to save config: %v", err))
	}
}

func (o *oracleKeyVaultStorage) Get(key core.ConfigKey) string {
	if val, ok := o.config[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}

	return ""

}

func (o *oracleKeyVaultStorage) Set(key core.ConfigKey, value interface{}) map[string]interface{} {
	o.config[key] = value
	convertedConfig := make(map[string]interface{})
	for k, v := range o.config {
		convertedConfig[string(k)] = v
	}

	o.SaveStorage(convertedConfig)
	return o.ReadStorage()
}

func (o *oracleKeyVaultStorage) Delete(key core.ConfigKey) map[string]interface{} {
	if _, found := o.config[key]; found {
		delete(o.config, key)
		olog.Debug(fmt.Sprintf("Deleted key '%s' from config", string(key)))
		o.saveConfig(o.config, false)
	} else {
		olog.Error(fmt.Sprintf("Key '%s' not found in config", string(key)))
	}

	return o.ReadStorage()
}

func (o *oracleKeyVaultStorage) DeleteAll() map[string]interface{} {
	o.config = map[core.ConfigKey]interface{}{}
	o.saveConfig(o.config, false)
	return o.ReadStorage()
}

func (o *oracleKeyVaultStorage) IsEmpty() bool {
	return len(o.config) == 0
}

func (o *oracleKeyVaultStorage) Contains(key core.ConfigKey) bool {
	_, found := o.config[key]
	return found
}
