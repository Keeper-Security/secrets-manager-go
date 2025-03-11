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
```
package main

import (
	"encoding/json"
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
	azurekv "github.com/keeper-security/secrets-manager-go/integrations/azure"
)

func main() {
	decryptConfig := false
	changeKey := false
	ksmConfigFileName := "ksm-config.json" // Change the file name accordingly to your config file
	keyURL := "<Key URL>"         // KeyURL of the key
	oneTimeToken := "One Time Token"

	//Initialize the Azure Key Vault Storage
	cfg := azurekv.NewAzureKeyValueStorage(ksmConfigFileName, keyURL, &azurekv.AzureConfig{
		TenantID:     "<Some Tenant ID>",
		ClientID:     "<Some Client ID>",
		ClientSecret: "<Some Client Secret>",
	})

	// Print the value of Client ID from the config
	fmt.Printf("key value: %s", cfg.Get(core.KEY_CLIENT_ID))

	// create a new secrets manager client
	secrets_manager := core.NewSecretsManager(
		&core.ClientOptions{
			Config: cfg,
			Token:  oneTimeToken,
		},
	)

	// Fetch all the secrets from the vault
	secrets, err := secrets_manager.GetSecrets([]string{})
	if err != nil {
		// do something
		fmt.Printf("Error while fetching secrets: %v", err)
	}

	// Print all the secrets
	for _, record := range secrets {
		fmt.Printf("Records: %v\n", record)
	}

	if changeKey {
		updatedConfig := &azurekv.AzureConfig{
			TenantID:     "<Updated Tenant ID>",
			ClientID:     "<Updated Client ID>",
			ClientSecret: "<Updated Client Secret>",
		}
		updatedKeyURL := "<Updated Key URL>"

		// Changes the key
		// If you don't want to change Config, pass nil as a paramter
		isChanged, err := cfg.ChangeKey(updatedKeyURL, updatedConfig)
		if err != nil {
			fmt.Printf("Error while changing key: %v", err)
		} else {
			fmt.Printf("Key changed: %v\n", isChanged)
		}
	}

	// Decrypt the config
	if decryptConfig {
		configs := make(map[core.ConfigKey]interface{})
		plainText, err := cfg.DecryptConfig(decryptConfig)
		if err != nil {
			// do something
			fmt.Printf("Error while decrypting config: %v", err)
		} else {
			if err := json.Unmarshal([]byte(plainText), &configs); err != nil {
				fmt.Printf("Error while unmarshalling: %v", err)
			}
			fmt.Printf("Decrypted data: %v\n", configs["clientId"])
		}
	}
}
```
# Configuration
The NewAzureKeyValueStorage requires the following parameters to encrypt the KSM configuration using Azure Key Vault:
* `ksmConfigFileName` : The file name of KSM configuration.
* `AzureConfig` : Provide azure credentails `TenantID` , `ClientID` and `ClientSecret`.
* `KeyURL` : The name of the key resource to be used for encryption/decryption.


KeyURL must be like this `https://<vault-name>.vault.azure.net/keys/<key-name>/<version>`

For more information about URL see the Azure Documentation 
https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#object-identifiers

You will need an Azure App directory App to use the Azure Key Vault integration.

For more information on Azure App Directory App registration and Permissions see the Azure documentation: https://learn.microsoft.com/en-us/azure/key-vault/general/authentication

You're ready to use the KSM integration 👍

Using the Azure Key Vault Integration

Review the SDK usage. Refer to the SDK (documentation) [https://docs.keeper.io/en/privileged-access-manager/secrets-manager/developer-sdk-library/golang-sdk#retrieve-secrets].