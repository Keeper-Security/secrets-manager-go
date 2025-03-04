# Azure Key Vault

Protect Secrets Manager connection details with Azure Key Vault

Keeper Secrets Manager integrates with Azure Key Vault in order to provide protection for Keeper Secrets Manager configuration files.  With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

# Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with Azure Key Vault
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Go-Lang SDK functionality

# Prerequisites

* Supports the Go-Lang Secrets Manager SDK.
* Requires Azure packages: azure-identity and azure-keyvault-client.
* Works with just RSA key types with `WrapKey` and `UnWrapKey` permissions.

# Setup
1. Install Secret-Manager-Go Package

The Secrets Manager azure package are located in the Keeper Secrets Manager storage package which can be installed using 

> `go get github.com/keeper-security/secrets-manager-go/integrations/azure`

Configure Azure Connection

configuration variables can be provided as 

```
import (
	"github.com/keeper-security/secrets-manager-go/core"
	azurekv "github.com/keeper-security/secrets-manager-go/azurekv"
)

key := azurekv.AzureConfig{
		TenantID:     "<Some Tenant ID>",
		ClientID:     "<Some Client ID>",
		ClientSecret: "<Some Client Secret>",
		KeyURL:     "<Key URL>",
}

cfg := azurekv.NewAzureKeyValueStorage("ksm-config.json", &key)clientOptions := &core.ClientOptions{
	Token:  "[One Time Access Token]",
	Config: cfg,
}

secrets_manager := core.NewSecretsManager(clientOptions)

// Fetch secrets from Keeper Security Vault 
record_uids := []string{}
records, err := secrets_manager.GetSecrets(record_uids)
if err != nil {
	// do something
}

for _, record := range records {
		// do something with record
		fmt.Println(record.Title())
}

updatedKey := azurekv.AzureConfig{
		TenantID:     "<Updated Tenant ID>",
		ClientID:     "<Updated Client ID>",
		ClientSecret: "<Updated Client Secret>",
		KeyURL:     "<Updated Key URL>",
}

// isChanged gives boolean value to check the key is changed or not.
isChanged, err := cfg.ChangeKey(updatedKey)
if err != nil {
	// do something
}

plainText, err := cfg.DecryptConfig(true)
if err != nil {
	// do something
}

fmt.Println(plainText)
```
The storage will require an Azure Key URL, as well Secrets Manager configuration which will be encrypted by Azure Key Vault.

Provide `TenantID` , `ClientID` , `ClientSecret` and `KeyURL` variables.

KeyURL must be like this `https://<vault-name>.vault.azure.net/keys/<key-name>/<version>`

For more information about URL see the Azure Documentation 
https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#object-identifiers

You will need an Azure App directory App to use the Azure Key Vault integration.

For more information on Azure App Directory App registration and Permissions see the Azure documentation: https://learn.microsoft.com/en-us/azure/key-vault/general/authentication

You're ready to use the KSM integration 👍

Using the Azure Key Vault Integration

Review the SDK usage. Refer to the SDK (documentation) [https://docs.keeper.io/en/privileged-access-manager/secrets-manager/developer-sdk-library/golang-sdk#retrieve-secrets].