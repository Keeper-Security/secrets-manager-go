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
		sm := ksm.NewSecretsManager()
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

	if err := os.Chdir(tempDirName); err == nil {
		rawJson := `
{
	"hostname": "fake.keepersecurity.com",
	"appKey": "9vVajcvJTGsa2Opc/jvhEiJLRKHtg2Rm4PAtUoP3URw=",
	"clientId": "rYebZN1TWiJagL+wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW+NNHDaq/8SQQ2sOYYT1Nhk5Ya/SkQ==",
	"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU+/LBMQQGfJAycwOtx9djH0YEvBT+hRANCAASB1L44QodSzRaIOhF7f/2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI",
	"serverPublicKeyId": "7"
}
		`
		if err := ioutil.WriteFile(defaultConfigName, []byte(rawJson), 0644); err == nil {
			sm := ksm.NewSecretsManager()
			if sm.Config.Get(ksm.KEY_HOSTNAME) != "fake.keepersecurity.com" {
				t.Error("did not get correct hostname")
			}
			if sm.Config.Get(ksm.KEY_APP_KEY) != "9vVajcvJTGsa2Opc/jvhEiJLRKHtg2Rm4PAtUoP3URw=" {
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

	if err := os.Chdir(tempDirName); err == nil {
		rawJson := `
{
	"appKey": "9vVajcvJTGsa2Opc/jvhEiJLRKHtg2Rm4PAtUoP3URw=",
	"clientId": "rYebZN1TWiJagL+wHxYboe1vPje10zx1JCJR2bpGILlhIRg7HO26C7HnW+NNHDaq/8SQQ2sOYYT1Nhk5Ya/SkQ==",
	"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo=",
	"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU+/LBMQQGfJAycwOtx9djH0YEvBT+hRANCAASB1L44QodSzRaIOhF7f/2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI",
	"serverPublicKeyId": "7"
}
		`
		if err := ioutil.WriteFile(defaultConfigName, []byte(rawJson), 0644); err == nil {
			// Pass in the client key and hostname
			sm := ksm.NewSecretsManagerFromSettings("ABC123", "localhost", true)
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
	b64ConfigStr := "eyAgICAgImFwcEtleSI6ICI4S3gyNVN2dGtSU3NFWUl1cjdtSEt0THFBTkZOQjdBWlJhOWNxaTJQU1FFPSIsICAgICAiY2x" +
		"pZW50SWQiOiAiNEgvVTVKNkRjZktMWUJJSUFWNVl3RUZHNG4zWGhpRHZOdG9Qa21TTUlUZVROWnNhL0VKMHpUYnBBQ1J0bU" +
		"5VQlJIK052UisyNHNRaFU5dUdqTFRaSHc9PSIsICAgICAiaG9zdG5hbWUiOiAia2VlcGVyc2VjdXJpdHkuY29tIiwgICAgI" +
		"CJwcml2YXRlS2V5IjogIk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3VoekRJNGlW" +
		"UzVCdzlsNWNmZkZYcFArRmh1bE5INDFHRFdWY3NiZ1h5aU9oUkFOQ0FBVGsxZnpvTDgvVkxwdVl1dTEzd0VsUE5wM2FHMmd" +
		"sRmtFUHp4YWlNZ1ArdnRVZDRnWjIzVHBHdTFzMXRxS2FFZTloN1ZDVk1qd3ZEQTMxYW5mTWxZRjUiLCAgICAgInNlcnZlcl" +
		"B1YmxpY0tleUlkIjogIjEwIiB9"

	token := "US:ABC123"
	hostname := "localhost"
	config := ksm.NewMemoryKeyValueStorage(b64ConfigStr)
	secretsManager := ksm.NewSecretsManagerFromFullSetup(token, hostname, true, config)

	if secretsManager.HostName != "keepersecurity.com" {
		t.Error("did not get correct server")
	}
	if strings.TrimSpace(secretsManager.Token) != "ABC123" {
		t.Error("One time token/Client key don't match")
	}

	if secretsManager.Config.Get(ksm.KEY_HOSTNAME) != "keepersecurity.com" {
		t.Error("did not get correct server")
	}
	if secretsManager.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
		t.Error("Client key is still present")
	}
}
func TestOnetimeTokenFormatsHostname(t *testing.T) {
	b64ConfigStr := "eyAgICAgImFwcEtleSI6ICI4S3gyNVN2dGtSU3NFWUl1cjdtSEt0THFBTkZOQjdBWlJhOWNxaTJQU1FFPSIsICAgICAiY2x" +
		"pZW50SWQiOiAiNEgvVTVKNkRjZktMWUJJSUFWNVl3RUZHNG4zWGhpRHZOdG9Qa21TTUlUZVROWnNhL0VKMHpUYnBBQ1J0bU" +
		"5VQlJIK052UisyNHNRaFU5dUdqTFRaSHc9PSIsICAgICAiaG9zdG5hbWUiOiAia2VlcGVyc2VjdXJpdHkuY29tIiwgICAgI" +
		"CJwcml2YXRlS2V5IjogIk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3VoekRJNGlW" +
		"UzVCdzlsNWNmZkZYcFArRmh1bE5INDFHRFdWY3NiZ1h5aU9oUkFOQ0FBVGsxZnpvTDgvVkxwdVl1dTEzd0VsUE5wM2FHMmd" +
		"sRmtFUHp4YWlNZ1ArdnRVZDRnWjIzVHBHdTFzMXRxS2FFZTloN1ZDVk1qd3ZEQTMxYW5mTWxZRjUiLCAgICAgInNlcnZlcl" +
		"B1YmxpY0tleUlkIjogIjEwIiB9"

	token := "fake.keepersecurity.com:ABC123"
	hostname := "localhost"
	config := ksm.NewMemoryKeyValueStorage(b64ConfigStr)
	secretsManager := ksm.NewSecretsManagerFromFullSetup(token, hostname, true, config)

	if secretsManager.HostName != "fake.keepersecurity.com" {
		t.Error("did not get correct server")
	}
	if strings.TrimSpace(secretsManager.Token) != "ABC123" {
		t.Error("One time token/Client key don't match")
	}

	if secretsManager.Config.Get(ksm.KEY_HOSTNAME) != "fake.keepersecurity.com" {
		t.Error("did not get correct server")
	}
	if secretsManager.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
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
		sm := ksm.NewSecretsManagerFromConfig(config)

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
	sm := ksm.NewSecretsManagerFromConfig(config)

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
	sm := ksm.NewSecretsManagerFromConfig(config)
	if sm.DefaultKeeperServerPublicKeyId() != sm.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) {
		t.Error("the public key is not set the default")
	}

	// Test if the config is edited and a bad key is entered that we go back to the default.
	config.Set(ksm.KEY_SERVER_PUBLIC_KEY_ID, "1_000_000")
	sm = ksm.NewSecretsManagerFromConfig(config)
	if sm.DefaultKeeperServerPublicKeyId() != sm.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) {
		t.Error("the public key is not set the default after bad key id")
	}
}

func TestInMemoryBase64Config(t *testing.T) {
	// JSON:
	// {
	//     "appKey": "MY APP KEY",
	//     "clientId": "MY CLIENT ID",
	//     "hostname": "fake.keepersecurity.com",
	//     "privateKey": "MY PRIVATE KEY",
	//     "serverPublicKeyId": "7"
	// }
	//
	// The above JSON in base64:
	// eyJhcHBLZXkiOiJNWSBBUFAgS0VZIiwiY2xpZW50SWQiOiJNWSBDTElFTlQgSUQiLCJob3N0bmFtZSI6ImZha2Uua2VlcGVyc2VjdXJpdHkuY29tIiwicHJpdmF0ZUtleSI6Ik1ZIFBSSVZBVEUgS0VZIiwic2VydmVyUHVibGljS2V5SWQiOiI3In0=

	base64ConfigStr := "eyJhcHBLZXkiOiJNWSBBUFAgS0VZIiwiY2xpZW50SWQiOiJNWSBDTElFTlQgSUQiLCJob3N0bmFtZSI6" +
		"ImZha2Uua2VlcGVyc2VjdXJpdHkuY29tIiwicHJpdmF0ZUtleSI6Ik1ZIFBSSVZBVEUgS0VZIiwic2Vy" +
		"dmVyUHVibGljS2V5SWQiOiI3In0="
	secretsManager := ksm.NewSecretsManagerFromConfig(ksm.NewMemoryKeyValueStorage(base64ConfigStr))
	dictConfig := secretsManager.Config.ReadStorage()

	success := false
	if key, ok := dictConfig[string(ksm.KEY_APP_KEY)]; ok {
		if val, ok := key.(string); ok && val == "MY APP KEY" {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect app key")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_CLIENT_ID)]; ok {
		if val, ok := key.(string); ok && val == "MY CLIENT ID" {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect client id")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_HOSTNAME)]; ok {
		if val, ok := key.(string); ok && val == "fake.keepersecurity.com" {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect hostname")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_PRIVATE_KEY)]; ok {
		if val, ok := key.(string); ok && val == "MY PRIVATE KEY" {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect private key")
	}

	success = false
	if key, ok := dictConfig[string(ksm.KEY_SERVER_PUBLIC_KEY_ID)]; ok {
		if val, ok := key.(string); ok && val == "7" {
			success = true
		}
	}
	if !success {
		t.Error("got incorrect server public key id")
	}

	// Pass in the config
	secretsManager = ksm.NewSecretsManagerFromConfig(secretsManager.Config)
	// not bound, client id and private key will be generated and overwrite existing
	if secretsManager.Config.Get(ksm.KEY_CLIENT_ID) == "" {
		t.Error("did not get a client id")
	}
	if secretsManager.Config.Get(ksm.KEY_PRIVATE_KEY) == "" {
		t.Error("did not get a private key")
	}
	if secretsManager.Config.Get(ksm.KEY_APP_KEY) == "" {
		t.Error("did not get an app key")
	}
	if secretsManager.Config.Get(ksm.KEY_HOSTNAME) == "" {
		t.Error("did not get a hostname")
	}
	if secretsManager.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) == "" {
		t.Error("did not get a public key id")
	}

	// Client key (one time token) should be removed
	if secretsManager.Config.Get(ksm.KEY_CLIENT_KEY) != "" {
		t.Error("found client key (one time token), should be missing.")
	}
}
