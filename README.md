# Secrets Manager Go SDK

![Go](https://github.com/keeper-security/secrets-manager-go/actions/workflows/test.go.yml/badge.svg)

This library provides interface to Keeper® Secrets Manager and can be used to access your Keeper vault, read and update existing records, rotate passwords and more. Keeper Secrets Manager is an open source project with contributions from Keeper's engineering team and partners.

## Features:

## Obtain a One-Time Access Token
Keeper Secrets Manager authenticates your API requests using advanced encryption that uses locally stored private key, device id and client id.
To register your device and generate private key you will need to generate a One-Time Access Token via Web Vault or Keeper Commander CLI.

### Via Web Vault
**Secrets Manager > Applications > Create Application** - will let you chose application name, shared folder(s) and permissions and generate One-Time Access Token. _Note: Keeper does not store One-Time Access Tokens - save or copy the token offline for later use._

One-Time Access Tokens can be generated as needed: **Secrets Manager > Applications > Application Name > Devices Tab > Edit > Add Device button** - will let you create new Device and generate its One-Time Access Token.

[What is an application?](https://docs.keeper.io/secrets-manager/secrets-manager/overview/terminology)

### Via Keeper Commander CLI
Login to Keeper with Commander CLI and perform following:
1. Create Application
    ```bash
   $ sm app create [NAME]
    ```

2. Share Secrets to the Application
    ```bash
   $ sm share add --app [NAME] --secret [UID] --editable
    ```
    - `--app` - Name of the Application.
    - `--secret` - Record UID or Shared Folder UID
    - `--editable` - if omitted defaults to false

3. Create client
    ```bash
   $ sm client add --app [NAME] --unlock-ip --count 1
    ```

### Install
```bash
go get github.com/keeper-security/secrets-manager-go/core
```

### Quick Start

```golang
package main

// Import Secrets Manager
import ksm "github.com/keeper-security/secrets-manager-go/core"

func main() {
	// Establish connection
	// One time secrets generated via Web Vault or Commander CLI
	hostname := "keepersecurity.com"
	token := "<One Time Access Token>"
	verfySllCerts := true
	config := ksm.NewFileKeyValueStorage("ksm-config.json")
	sm := ksm.NewSecretsManagerFromFullSetup(token, hostname, verfySllCerts, config)
	// One time tokens can be used only once - afterwards use the generated config file
	// sm := ksm.NewSecretsManagerFromConfig(ksm.NewFileKeyValueStorage("client-config.json"))

	// Retrieve all password records
	allRecords, _ := sm.GetSecrets([]string{})

	// Get password from first record:
	password := allRecords[0].Password()

	// WARNING: Avoid logging sensitive data
	print("My password from Keeper: ", password)
}
```

## Samples
### File Download
```golang
sm := ksm.NewSecretsManagerFromConfig(ksm.NewFileKeyValueStorage("client-config.json"))

if records, err := sm.GetSecrets([]string{}); err == nil {
	for _, r := range records {
		fmt.Println("\tTitle: " + r.Title())
		for i, f := range r.Files {
			fmt.Printf("\t\tfile #%d -> name: %s", i, f.Name)
			f.SaveFile("/tmp/"+f.Name, true)
		}
	}
}
```

### Update record
```golang
sm := ksm.NewSecretsManagerFromConfig(ksm.NewFileKeyValueStorage("client-config.json"))

if records, err := sm.GetSecrets([]string{}); err == nil && len(records) > 0 {
	record := records[0]
	newPassword := fmt.Sprintf("Test Password - " + time.Now().Format(time.RFC850))
	record.SetPassword(newPassword)
	record.RawJson = ksm.DictToJson(record.RecordDict)

	if err := sm.Save(record); err != nil {
		fmt.Println("Error saving record: " + err.Error())
	}
}
```

## Configuration

### Types

Listed in priority order
1. Environment variable
1. Configuration store
1. Code

### Available configurations:

- `clientKey` - One Time Access Token used during initialization
- `hostname` - Keeper Backend host. Available values:
    - `keepersecurity.com`
    - `keepersecurity.eu`
    - `keepersecurity.com.au`
    - `govcloud.keepersecurity.us`

## Adding more records or shared folders to the Application

### Via Web Vault
Drag&Drop records into the shared folder or select from the record menu any of the options to CreateDuplicate/Move or create new records straight into the shared folder. As an alternative use: **Secrets Manager > Application > Application Name > Folders & Records > Edit** and use search field to add any folders or records then click Save.

### Via Commander CLI
```bash
sm share add --app [NAME] --secret [UID2]
sm share add --app [NAME] --secret [UID3] --editable
```

### Retrieve secret(s)
```golang
secretsManager := ksm.NewSecretsManagerFromConfig(ksm.NewFileKeyValueStorage("client-config.json"))
allSecrets, _ := secretsManager.GetSecrets([]string{})
```

### Update secret
```golang
secretToUpdate = allSecrets[0]

secretToUpdate.SetPassword("NewPassword123$")

secretsManager.Save(secretToUpdate)
```
