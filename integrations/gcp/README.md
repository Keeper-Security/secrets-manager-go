# GCP Cloud Key Management

Protect Secrets Manager connection details with GCP Cloud Key Management 

Keeper Secrets Manager integrates with GCP Cloud Key Management in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.

# Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with GCP Cloud Key Management 
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Go-Lang SDK functionality

# Prerequisites
* Supports the Go-Lang Secrets Manager SDK.
* Requires GCP Cloud packages: kms/apiv1, kmspb, core, kms
* Works with just AES/RSA key types with `Encrypt` and `Decrypt` permissions.

# Setup
1. Install Secret-Manager-Go Package

The Secrets Manager GCP package are located in the Keeper Secrets Manager storage package which can be installed using 

> `go get github.com/keeper-security/secrets-manager-go/integrations/gcp`

Configure GCP Connection

```

package main

import (
	"encoding/json"
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
	gcpkv "github.com/keeper-security/secrets-manager-go/integrations/gcp"
)

func main() {
	decryptConfig := false
	changeKey := false

	credentialFileWithPath := "<Location of credential file ending with .json>"
	keyResourceName := "<Key Resource Name>"
	ksmConfigFileName := ""
	oneTimeToken := "<One Time Access Token>"

	cfg := gcpkv.NewGCPKeyVaultStorage(ksmConfigFileName, keyResourceName, credentialFileWithPath)

	client_options := &core.ClientOptions{
		Token:  oneTimeToken,
		Config: cfg,
	}

	fmt.Printf("Client ID Value: %s", cfg.Get(core.KEY_CLIENT_ID))

	secrets_manager := core.NewSecretsManager(client_options)
	secrets, err := secrets_manager.GetSecrets([]string{})
	if err != nil {
		// do something
		fmt.Printf("Error while fetching secrets: %v\n", err)
	}

	for _, record := range secrets {
		fmt.Printf("Records: %v\n", record)
	}

	if changeKey {
		// isChanged gives boolean value to check the key is changed or not.
		// Pass (updatedResourceName, "") as a parameter to change the key. Its just change the key for encryption and decryption.
		updatedResourceName := "<Updated Key Resource Name>"
		isChanged, err := cfg.ChangeKey(updatedResourceName, "")
		if err != nil {
			// do something
		}

		fmt.Printf("Key changed: %v\n", isChanged)

		// Pass updated service account credentials along with the updated key if you need to change the credentails.
		// Pass (updatedResourceName, updatedCredentialFileWithPath) as a parameter.
		// updatedCredentialFileWithPath := "<Updated Location of credential file ending with .json>"
		// isChanged, err = cfg.ChangeKey(updatedResourceName, updatedCredentialFileWithPath)
		// if err != nil {
		// 	// do something
		// 	fmt.Printf("Error while changing key: %v\n", err)
		// } else {
		// 	fmt.Printf("Key changed: %v\n", isChanged)
		// }

		// fmt.Printf("Client ID Value after changing Key: %s", cfg.Get(core.KEY_CLIENT_ID))
	}

	if decryptConfig {
		configs := make(map[core.ConfigKey]interface{})
		// Decrypt the config
		// Pass true as a parameter to save the decrypted config in the given file, else pass false
		plainText, err := cfg.DecryptConfig(false)
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
The NewGCPKeyVaultStorage requires the following parameters to encrypt the KSM configuration using GCP Cloud Key Management:

* `ksmConfigFileName` : The file name of KSM configuration.
* `GCP CredentialFile` :  The file name along with its path for the GCP credential file.
* `KeyResourceName` : The name of the key resource to be used for encryption/decryption.

KeyResourceName format must be `projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME/cryptoKeyVersions/KEY_VERSION`

For more information about KeyResourceName see the GCP Cloud Key Management Documentation 
https://cloud.google.com/kms/docs/getting-resource-ids

You're ready to use the KSM integration 👍

Using the GCP Cloud Key Management Integration

Review the SDK usage. Refer to the SDK (documentation) [https://docs.keeper.io/en/privileged-access-manager/secrets-manager/developer-sdk-library/golang-sdk#retrieve-secrets].
