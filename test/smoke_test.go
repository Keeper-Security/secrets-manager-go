package test

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestTheWorks(t *testing.T) {
	// Perform a simple get_secrets
	// This test is mocked to return 3 record (2 records, 1 folder with a record)
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	if f, err := ioutil.TempFile("", ""); err == nil {
		defer func() {
			f.Close()
			os.Remove(f.Name())
		}()
		if err := ioutil.WriteFile(f.Name(), []byte(configJson), 0644); err == nil {
			config := ksm.NewFileKeyValueStorage(f.Name())
			sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

			// --------------------------
			// Add three records, 2 outside a folder, 1 inside folder
			res1 := NewMockResponse([]byte{}, 200, nil)
			one := res1.AddRecord("My Record 1", "", "", nil, nil)
			one.Field("login", "", "", "", "My Login 1")
			one.Field("password", "", "", "", "My Password 1")
			one.CustomField("text", "My Custom 1", "", "", "custom1")

			// The frontend allows for custom field to not have unique names :(. The best way we
			// can handle this is to set label and field type.
			one.CustomField("text", "My Custom 2", "", "", "custom2")
			one.CustomField("secret", "My Custom 2", "", "", "my secret")

			two := res1.AddRecord("My Record 2", "", "", nil, nil)
			two.Field("login", "", "", "", "My Login 2")
			two.Field("password", "", "", "", "My Password 2")
			two.AddFile("My File 1", "", "", "", nil, 0)
			two.AddFile("My File 2", "", "", "", nil, 0)

			folder := res1.AddFolder("", nil)
			three := folder.AddRecord("My Record 3", "", "", nil)
			three.Field("login", "", "", "", "My Login 3")
			three.Field("password", "", "", "", "My Password 3")

			// --------------------------
			res2 := NewMockResponse([]byte{}, 200, nil)

			// Use the existing first record of res1
			res2.AddRecord("", "", "", one, nil)

			// --------------------------

			// All records
			MockResponseQueue.AddMockResponse(res1)
			// Single record
			MockResponseQueue.AddMockResponse(res2)
			// Save response
			MockResponseQueue.AddMockResponse(NewMockResponse([]byte{}, 200, nil))
			// Save with error
			// Make the error message
			errorJson := `{
				"path": "https://fake.keepersecurity.com/api/rest/sm/v1/update_secret, POST, Go-http-client/1.1",
				"additional_info": "",
				"location": "some location",
				"error": "access_denied",
				"message": "You can't update because of spite"
			}`
			MockResponseQueue.AddMockResponse(NewMockResponse([]byte(errorJson), 403, nil))

			// --------------------------
			// DO THE WORKS
			records, err := sm.GetSecrets([]string{""})
			if err != nil || len(records) != 3 {
				t.Error("didn't get 3 records")
			}

			records, err = sm.GetSecrets([]string{one.Uid})
			if err != nil || len(records) != 1 {
				t.Error("didn't get 1 records")
			}
			record := records[0]

			// Test field gets
			if login := record.GetFieldValueByType("login"); login != "My Login 1" {
				t.Error("didn't get the correct login")
			}

			if loginValues := record.GetFieldValuesByType("login"); len(loginValues) != 1 {
				t.Error("didn't find only 1 login")
			} else if loginValues[0] != "My Login 1" {
				t.Error("didn't get the correct login in array")
			}

			// Test custom field gets
			if custom := record.GetCustomFieldValueByLabel("My Custom 1"); custom != "custom1" {
				t.Error("didn't get the correct My Custom 1 value")
			}
			if custom := record.GetCustomFieldValues("My Custom 2", "text"); len(custom) != 1 || custom[0] != "custom2" {
				t.Error("didn't get the correct My Custom 2/text value")
			}
			if custom := record.GetCustomFieldValues("My Custom 2", "secret"); len(custom) != 1 || custom[0] != "my secret" {
				t.Error("didn't get the correct My Custom 2/secret value")
			}

			// Test field sets
			record.SetFieldValueSingle("login", "ABC")
			if login := record.GetFieldValueByType("login"); login != "ABC" {
				t.Error("didn't get the correct login for str")
			}

			// Test custom field sets
			record.SetCustomFieldValueSingle("My Custom 1", "NEW VALUE")
			if custom := record.GetCustomFieldValueByLabel("My Custom 1"); custom != "NEW VALUE" {
				t.Error("didn't get the correct My Custom 1 value after set")
			}

			// SAVE THE RECORD
			sm.Save(record)

			// While we are here, save again with error response
			func() {
				defer func() {
					if r := recover(); r != nil {
						expectedMsg := "POST Error: Error: access_denied, message=You can't update because of spite"
						if msg, ok := r.(string); ok && strings.TrimSpace(msg) == expectedMsg {
							t.Log("Received expected error message: " + msg)
						} else {
							t.Error("did not get correct exception")
						}
					}
				}()
				if err := sm.Save(record); err == nil {
					t.Error("the second save should have failed but didn't")
				}
			}()

			// Take the save record and queue it back up as a response.
			savedRes := NewMockResponse([]byte{}, 200, nil)
			savedRes.AddRecord("", "", "", nil, record)
			MockResponseQueue.AddMockResponse(savedRes)

			records, err = sm.GetSecrets([]string{record.Uid})
			if err != nil || len(records) != 1 {
				t.Error("didn't get 1 records")
			}
			record = records[0]
			if custom := record.GetCustomFieldValueByLabel("My Custom 1"); custom != "NEW VALUE" {
				t.Error("didn't get the correct My Custom 1 value after write")
			}
		} else {
			t.Error(err.Error())
		}
	} else {
		t.Error(err.Error())
	}
}

func TestVerifySslCerts(t *testing.T) {
	mockConfig := MockConfig{}.MakeConfig([]string{"clientKey"}, "EU:1234", "", "")
	base64ConfigStr := MockConfig{}.MakeBase64(mockConfig)

	config := ksm.NewMemoryKeyValueStorage(base64ConfigStr)

	os.Setenv("KSM_SKIP_VERIFY", "")
	if sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}); !sm.VerifySslCerts {
		t.Error(" VerifySslCerts is not true on 'no args; instance")
	}

	os.Setenv("KSM_SKIP_VERIFY", "")
	if sm := ksm.NewSecretsManager(&ksm.ClientOptions{Token: "1234", Hostname: "EU", InsecureSkipVerify: false, Config: config}); !sm.VerifySslCerts {
		t.Error(" VerifySslCerts is not true on param instance")
	}

	os.Setenv("KSM_SKIP_VERIFY", "")
	if sm := ksm.NewSecretsManager(&ksm.ClientOptions{Token: "1234", Hostname: "EU", InsecureSkipVerify: true, Config: config}); sm.VerifySslCerts {
		t.Error(" VerifySslCerts is not false on param instance")
	}

	os.Setenv("KSM_SKIP_VERIFY", "FALSE")
	if sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}); !sm.VerifySslCerts {
		t.Error(" VerifySslCerts is not false on env set (FALSE)")
	}

	os.Setenv("KSM_SKIP_VERIFY", "NO")
	if sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}); !sm.VerifySslCerts {
		t.Error(" VerifySslCerts is not false on env set (NO)")
	}

	os.Setenv("KSM_SKIP_VERIFY", "True")
	if sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}); sm.VerifySslCerts {
		t.Error(" VerifySslCerts is not true on env set (True)")
	}
}
