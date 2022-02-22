package test

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestMissingConfig(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			expectedMsg := "Cannot locate One Time Token."
			if msg, ok := r.(string); !ok || strings.TrimSpace(msg) != expectedMsg {
				t.Error("did not get correct exception message.")
			}
		}
	}()

	// Attempt to load a missing config file.

	// Attempt to get instance without config file. This should fail since the directory will not contain
	// any config file and there are no env vars to use.
	if curWD, err := os.Getwd(); err == nil {
		defer os.Chdir(curWD) // Fix for Windows cleanup error ...being used by another process
	}

	// tempDirName := t.TempDir()
	tempDirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Error(err.Error())
	}
	defer os.RemoveAll(tempDirName)

	if err := os.Chdir(tempDirName); err == nil {
		sm := ksm.NewSecretsManager(nil)
		t.Errorf("Found config file, should be missing. Config is empty: %t", sm.Config.IsEmpty())
	} else {
		t.Error(err.Error())
	}
}

func TestDefaultLoadFromJson(t *testing.T) {
	// Load config from default location and name.

	defaultConfigName := ksm.DEFAULT_CONFIG_PATH

	// Make instance using default config file.
	// Create a JSON config file and store under the default file name.
	// This will pass because the JSON file exists.
	if curWD, err := os.Getwd(); err == nil {
		defer os.Chdir(curWD) // Fix for Windows cleanup error ...being used by another process
	}

	// tempDirName := t.TempDir()
	tempDirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Error(err.Error())
	}
	defer os.RemoveAll(tempDirName)

	mockConfig := MockConfig{}.MakeConfig(nil, "", "")
	configJson := MockConfig{}.MakeJson(mockConfig)
	if err := os.Chdir(tempDirName); err == nil {
		if err := ioutil.WriteFile(defaultConfigName, []byte(configJson), 0644); err == nil {
			sm := ksm.NewSecretsManager(nil)
			if sm.Config.Get(ksm.KEY_HOSTNAME) != mockConfig["hostname"] {
				t.Error("did not get correct hostname")
			}
			if sm.Config.Get(ksm.KEY_APP_KEY) != mockConfig["appKey"] {
				t.Error("did not get correct app key")
			}
		} else {
			t.Error(err.Error())
		}
	} else {
		t.Error(err.Error())
	}
}

func TestOverwriteViaArgs(t *testing.T) {
	// Load config from default location and name, but overwrite the client key and hostname

	defaultConfigName := ksm.DEFAULT_CONFIG_PATH

	// Make instance using default config file.
	// Create a JSON config file and store under the default file name.
	// This will pass because the JSON file exists.
	if curWD, err := os.Getwd(); err == nil {
		defer os.Chdir(curWD) // Fix for Windows cleanup error ...being used by another process
	}

	// tempDirName := t.TempDir()
	tempDirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Error(err.Error())
	}
	defer os.RemoveAll(tempDirName)

	mockConfig := MockConfig{}.MakeConfig(nil, "", "")
	configJson := MockConfig{}.MakeJson(mockConfig)
	if err := os.Chdir(tempDirName); err == nil {
		if err := ioutil.WriteFile(defaultConfigName, []byte(configJson), 0644); err == nil {
			// Pass in the client key and hostname
			sm := ksm.NewSecretsManager(&ksm.ClientOptions{Token: "ABC123", Hostname: "localhost"})
			if sm.Config.Get(ksm.KEY_HOSTNAME) != "localhost" {
				t.Error("did not get correct hostname")
			}
			if sm.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
				t.Error("found client key, should be missing.")
			}
		} else {
			t.Error(err.Error())
		}
	} else {
		t.Error(err.Error())
	}
}

func TestOnetimeTokenFormatsAbbrev(t *testing.T) {
	mockConfig := MockConfig{}.MakeConfig([]string{"clientKey"}, "", "")
	base64ConfigStr := MockConfig{}.MakeBase64(mockConfig)

	config := ksm.NewMemoryKeyValueStorage(base64ConfigStr)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Token: "US:ABC123", Hostname: "localhost", Config: config})

	if sm.Hostname != "keepersecurity.com" {
		t.Error("did not get correct server")
	}
	if strings.TrimSpace(sm.Token) != "ABC123" {
		t.Error("One time token/Client key don't match")
	}

	if sm.Config.Get(ksm.KEY_HOSTNAME) != "keepersecurity.com" {
		t.Error("did not get correct server")
	}
	if sm.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
		t.Error("Client key is still present")
	}
}
func TestOnetimeTokenFormatsHostname(t *testing.T) {
	mockConfig := MockConfig{}.MakeConfig([]string{"clientKey"}, "", "")
	base64ConfigStr := MockConfig{}.MakeBase64(mockConfig)

	config := ksm.NewMemoryKeyValueStorage(base64ConfigStr)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Token: "fake.keepersecurity.com:ABC123", Hostname: "localhost", Config: config})

	if sm.Hostname != "fake.keepersecurity.com" {
		t.Error("did not get correct server")
	}
	if strings.TrimSpace(sm.Token) != "ABC123" {
		t.Error("One time token/Client key don't match")
	}

	if sm.Config.Get(ksm.KEY_HOSTNAME) != "fake.keepersecurity.com" {
		t.Error("did not get correct server")
	}
	if sm.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
		t.Error("Client key is still present")
	}
}

func TestPassInConfig(t *testing.T) {
	defaultConfigName := ksm.DEFAULT_CONFIG_PATH

	// Make instance using default config file.
	// Create a JSON config file and store under the default file name.
	// This will pass because the JSON file exists.
	if curWD, err := os.Getwd(); err == nil {
		defer os.Chdir(curWD) // Fix for Windows cleanup error ...being used by another process
	}

	// tempDirName := t.TempDir()
	tempDirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Error(err.Error())
	}
	defer os.RemoveAll(tempDirName)

	if err := os.Chdir(tempDirName); err == nil {
		config := ksm.NewFileKeyValueStorage()
		config.Set(ksm.KEY_CLIENT_KEY, "MY CLIENT KEY")
		config.Set(ksm.KEY_CLIENT_ID, "MY CLIENT ID")
		config.Set(ksm.KEY_APP_KEY, "MY APP KEY")
		config.Set(ksm.KEY_PRIVATE_KEY, "MY PRIVATE KEY")

		if ok, err := ksm.PathExists(defaultConfigName); !ok {
			t.Error("config file is missing. " + err.Error())
		}

		dictConfig := config.ReadStorage()

		if val, ok := dictConfig[string(ksm.KEY_CLIENT_KEY)]; !ok || val != "MY CLIENT KEY" {
			t.Error("did not get correct client key")
		}
		if val, ok := dictConfig[string(ksm.KEY_CLIENT_ID)]; !ok || val != "MY CLIENT ID" {
			t.Error("did not get correct client id")
		}
		if val, ok := dictConfig[string(ksm.KEY_APP_KEY)]; !ok || val != "MY APP KEY" {
			t.Error("did not get correct app key")
		}
		if val, ok := dictConfig[string(ksm.KEY_PRIVATE_KEY)]; !ok || val != "MY PRIVATE KEY" {
			t.Error("did not get correct private key")
		}

		// Pass in the config
		sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config})

		// Is not bound, client id and private key will be generated and overwrite existing
		if sm.Config.Get(ksm.KEY_CLIENT_ID) == "" {
			t.Error("did not get a client id")
		}
		if sm.Config.Get(ksm.KEY_PRIVATE_KEY) == "" {
			t.Error("did not get a private key")
		}

		// Client key (one time token) should be removed
		if sm.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
			t.Error("found client key (one time token), should be missing.")
		}
	} else {
		t.Error(err.Error())
	}
}

func TestInMemoryConfig(t *testing.T) {
	config := ksm.NewMemoryKeyValueStorage()
	config.Set(ksm.KEY_CLIENT_KEY, "MY CLIENT KEY")
	config.Set(ksm.KEY_CLIENT_ID, "MY CLIENT ID")
	config.Set(ksm.KEY_APP_KEY, "MY APP KEY")
	config.Set(ksm.KEY_PRIVATE_KEY, "MY PRIVATE KEY")

	dictConfig := config.ReadStorage()

	if val, ok := dictConfig[string(ksm.KEY_CLIENT_KEY)]; !ok || val != "MY CLIENT KEY" {
		t.Error("did not get correct client key")
	}
	if val, ok := dictConfig[string(ksm.KEY_CLIENT_ID)]; !ok || val != "MY CLIENT ID" {
		t.Error("did not get correct client id")
	}
	if val, ok := dictConfig[string(ksm.KEY_APP_KEY)]; !ok || val != "MY APP KEY" {
		t.Error("did not get correct app key")
	}
	if val, ok := dictConfig[string(ksm.KEY_PRIVATE_KEY)]; !ok || val != "MY PRIVATE KEY" {
		t.Error("did not get correct private key")
	}

	// Pass in the config
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config})

	// not bound, client id and private key will be generated and overwrite existing
	if sm.Config.Get(ksm.KEY_CLIENT_ID) == "" {
		t.Error("did not get a client id")
	}
	if sm.Config.Get(ksm.KEY_PRIVATE_KEY) == "" {
		t.Error("did not get a private key")
	}

	// Client key (one time token) should be removed
	if sm.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
		t.Error("found client key (one time token), should be missing.")
	}
}

func TestPublicKeyId(t *testing.T) {
	config := ksm.NewMemoryKeyValueStorage()
	config.Set(ksm.KEY_CLIENT_KEY, "MY CLIENT KEY")
	config.Set(ksm.KEY_CLIENT_ID, "MY CLIENT ID")
	config.Set(ksm.KEY_APP_KEY, "MY APP KEY")
	config.Set(ksm.KEY_PRIVATE_KEY, "MY PRIVATE KEY")

	// Test the default setting of the key id if missing
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config})
	if sm.DefaultKeeperServerPublicKeyId() != sm.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) {
		t.Error("the public key is not set the default")
	}

	// Test if the config is edited and a bad key is entered that we go back to the default.
	config.Set(ksm.KEY_SERVER_PUBLIC_KEY_ID, "1_000_000")
	sm = ksm.NewSecretsManager(&ksm.ClientOptions{Config: config})
	if sm.DefaultKeeperServerPublicKeyId() != sm.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) {
		t.Error("the public key is not set the default after bad key id")
	}
}

func TestInMemoryBase64Config(t *testing.T) {
	mockConfig := MockConfig{}.MakeConfig([]string{"clientKey"}, "", "")
	base64ConfigStr := MockConfig{}.MakeBase64(mockConfig)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: ksm.NewMemoryKeyValueStorage(base64ConfigStr)})
	dictConfig := sm.Config.ReadStorage()

	success := false
	if key, ok := dictConfig[string(ksm.KEY_APP_KEY)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["appKey"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect app key")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_CLIENT_ID)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["clientId"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect client id")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_HOSTNAME)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["hostname"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect hostname")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_PRIVATE_KEY)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["privateKey"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect private key")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_SERVER_PUBLIC_KEY_ID)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["serverPublicKeyId"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect server public key id")
	}

	// Pass in the config
	sm = ksm.NewSecretsManager(&ksm.ClientOptions{Config: sm.Config})
	// not bound, client id and private key will be generated and overwrite existing
	if sm.Config.Get(ksm.KEY_CLIENT_ID) == "" {
		t.Error("did not get a client id")
	}
	if sm.Config.Get(ksm.KEY_PRIVATE_KEY) == "" {
		t.Error("did not get a private key")
	}
	if sm.Config.Get(ksm.KEY_APP_KEY) == "" {
		t.Error("did not get an app key")
	}
	if sm.Config.Get(ksm.KEY_HOSTNAME) == "" {
		t.Error("did not get a hostname")
	}
	if sm.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) == "" {
		t.Error("did not get a public key id")
	}

	// Client key (one time token) should be removed
	if sm.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
		t.Error("found client key (one time token), should be missing.")
	}
}

func TestInMemoryBase64ConfigViaEnv(t *testing.T) {
	mockConfig := MockConfig{}.MakeConfig([]string{"clientKey"}, "", "")
	base64ConfigStr := MockConfig{}.MakeBase64(mockConfig)

	// Put the config into env var,
	os.Setenv("KSM_CONFIG", base64ConfigStr)
	sm := ksm.NewSecretsManager(nil)
	dictConfig := sm.Config.ReadStorage()

	success := false
	if key, ok := dictConfig[string(ksm.KEY_APP_KEY)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["appKey"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect app key")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_CLIENT_ID)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["clientId"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect client id")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_HOSTNAME)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["hostname"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect hostname")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_PRIVATE_KEY)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["privateKey"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect private key")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_SERVER_PUBLIC_KEY_ID)]; ok {
		if val, ok := key.(string); ok && val == mockConfig["serverPublicKeyId"] {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect server public key id")
	}

	// Pass in the config
	sm = ksm.NewSecretsManager(&ksm.ClientOptions{Config: sm.Config})
	// not bound, client id and private key will be generated and overwrite existing
	if sm.Config.Get(ksm.KEY_CLIENT_ID) == "" {
		t.Error("did not get a client id")
	}
	if sm.Config.Get(ksm.KEY_PRIVATE_KEY) == "" {
		t.Error("did not get a private key")
	}
	if sm.Config.Get(ksm.KEY_APP_KEY) == "" {
		t.Error("did not get an app key")
	}
	if sm.Config.Get(ksm.KEY_HOSTNAME) == "" {
		t.Error("did not get a hostname")
	}
	if sm.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) == "" {
		t.Error("did not get a public key id")
	}

	// Client key (one time token) should be removed
	if sm.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
		t.Error("found client key (one time token), should be missing.")
	}
}
