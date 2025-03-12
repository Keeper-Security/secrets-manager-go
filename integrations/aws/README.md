**AWS Key Management**

Protect Secrets Manager connection details with AWS Key Management 

Keeper Secrets Manager integrates with  AWS Key Management in order to provide protection for Keeper Secrets Manager configuration files. With this integration, you can protect connection details on your machine while taking advantage of Keeper's zero-knowledge encryption of all your secret credentials.
Features

* Encrypt and Decrypt your Keeper Secrets Manager configuration files with AWS Key Management 
* Protect against unauthorized access to your Secrets Manager connections
* Requires only minor changes to code for immediate protection. Works with all Keeper Secrets Manager Go-Lang SDK functionality

Prerequisites

* Supports the Go-Lang Secrets Manager SDK.
* Requires AWS packages: aws, config, credentials, kms, kms-types
* Works with AES/RSA key types with `Encrypt` and `Decrypt` permissions.

Setup
1. Install Secret-Manager-Go Package

The Secrets Manager AWS package are located in the Keeper Secrets Manager storage package which can be installed using 

> `go get github.com/keeper-security/secrets-manager-go/integrations/aws`

Configure AWS Connection

```
package main

import (
	"encoding/json"
	"fmt"

	"github.com/keeper-security/secrets-manager-go/core"
	awskv "github.com/keeper-security/secrets-manager-go/integrations/aws"
)

func main() {
	decryptConfig := true
	changeKey := true

	clientID := "<Some Client ID>"
	clientSecret := "<Some Client Secret>"
	region := "<Cloud Region>"
	keyARN := "arn:<partition>:kms:<region>:<account-id>:key/<key-id>"
	oneTimeToken := "one time token"
	ksmConfigFileName := ""

	// Initialize the AWS Key Vault Storage
	cfg := awskv.NewAWSKeyValueStorage(ksmConfigFileName, keyARN, &awskv.AWSConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Region:       region,
	})

	clientOptions := &core.ClientOptions{
		Token:  oneTimeToken,
		Config: cfg,
	}

	fmt.Printf("Client ID in config: %v\n", cfg.Get(core.KEY_CLIENT_ID))

	secrets_manager := core.NewSecretsManager(clientOptions)
	// Fetch secrets from Keeper Security Vault
	record_uids := []string{}
	records, err := secrets_manager.GetSecrets(record_uids)
	if err != nil {
		// do something
		fmt.Printf("Error while fetching secrets: %v", err)
	}

	for _, record := range records {
		// do something with record
		fmt.Println(record.Title())
	}

	if changeKey {
		// Changes the key
		// If you don't want to change Config, pass nil as a paramter
		updatedKeyARN := "arn:<partition>:kms:<region>:<account-id>:key/<key-id>"
		isChanged, err := cfg.ChangeKey(updatedKeyARN, nil)
		if err != nil {
			// do something
			fmt.Printf("Error while changing key: %v", err)
		}

		fmt.Printf("Key is changed: %v \n", isChanged)
		fmt.Printf("Client ID in config after changing key: %v\n", cfg.Get(core.KEY_CLIENT_ID))
		// If you want to change the account credentials along with the updated key then pass updatedConfig as a paramter
		// updatedClientID := "<Updated Client ID>"
		// updatedClientSecret := "<Updated Client Secret>"
		// updatedRegion := "<Updated Region>"
		// updatedConfig := awskv.AWSConfig{
		// 	ClientID:     updatedClientID,
		// 	ClientSecret: updatedClientSecret,
		// 	Region:       updatedRegion,
		// }

		// isChanged gives boolean value to check the key is changed or not.
		// updatedConfig should be nil only when KeyARN need to change.
		// isChanged, err = cfg.ChangeKey(updatedKeyARN, &updatedConfig)
		// if err != nil {
		// 	// do something
		// 	fmt.Printf("Error while changing key: %v", err)
		// }

		// fmt.Printf("Key is changed: %v", isChanged)
	}

	configs := make(map[core.ConfigKey]interface{})
	if decryptConfig {
		// Decrypt the config
		// Pass true as a parameter to save the decrypted config in the given file, else pass false
		decryptedConfig, err := cfg.DecryptConfig(true)
		if err != nil {
			// do something
			fmt.Printf("Error while decrypting config: %v", err)
		} else {
			if err := json.Unmarshal([]byte(decryptedConfig), &configs); err != nil {
				// do something
				fmt.Printf("Error while unmarshalling decrypted config: %v", err)
			} else {
				fmt.Printf("Decrypted data: %v\n", configs["clientId"])
			}
		}

	}
}
```
# Configuration
The NewAWSKeyValueStorage requires the following parameters to encrypt the KSM configuration using GCP Cloud Key Management:
* `ksmConfigFileName` : The file name of KSM configuration.
* `KeyARN` : Key ARN of the key used for encryption/decryption. 
* `AWSConfig` : Provide `ClientID` , `ClientSecret` and `Region` variables.
* If you want to load credentials from Environment variable then pass nil in place of `AWSConfig`.

KeyARN must be like this `arn:<partition>:kms:<region>:<account-id>:key/<key-id>`

For more information about KeyARN see the AWS Key Management Documentation 
https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id

You're ready to use the KSM integration 👍

Using the AWS Key Management Integration

Review the SDK usage. Refer to the SDK (documentation) [https://docs.keeper.io/en/privileged-access-manager/secrets-manager/developer-sdk-library/golang-sdk#retrieve-secrets].