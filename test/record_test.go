package test

import (
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestLoginRecordPassword(t *testing.T) {
	// If the record type is login or general, the password is expected in fields[]
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	// A good record.
	// 'fields': [...{'type': 'password', 'value': ['My Password']}...]
	goodRes := NewMockResponse([]byte{}, 200, nil)
	good := goodRes.AddRecord("Good Record", "login", "", nil, nil)
	good.Field("login", "", "", "", "My Login")
	good.Field("password", "", "", "", "My Password")

	// A bad record. This would be like if someone removed a password text from an existing field.
	// 'fields': [...{'type': 'password', 'value': []}...]
	badRes := NewMockResponse([]byte{}, 200, nil)
	bad := badRes.AddRecord("Bad Record", "login", "", nil, nil)
	bad.Field("login", "", "", "", "My Login")
	bad.Field("password", "", "", "", []interface{}{})

	// An ugly record. The application didn't even add the field. We need to set flags to prune empty fields.
	// 'fields': [...]
	uglyRes := NewMockResponse([]byte{}, 200, &MockFlags{PruneEmptyFields: true})
	ugly := uglyRes.AddRecord("Ugly Record", "login", "", nil, nil)
	ugly.Field("login", "", "", "", "My Login")
	ugly.Field("password", "", "", "", []interface{}{}) // this will be removed from the fields array.

	MockResponseQueue.AddMockResponse(goodRes)
	MockResponseQueue.AddMockResponse(badRes)
	MockResponseQueue.AddMockResponse(uglyRes)

	records, err := sm.GetSecrets([]string{""})
	if err != nil || len(records) != 1 {
		t.Error("didn't get 1 record for the good")
	} else if records[0].Password() != "My Password" {
		t.Error("did not get correct password for the good")
	}

	records, err = sm.GetSecrets([]string{""})
	if err != nil || len(records) != 1 {
		t.Error("didn't get 1 record for the bad")
	} else if records[0].Password() != "" {
		t.Error("password is defined for the bad")
	}

	records, err = sm.GetSecrets([]string{""})
	if err != nil || len(records) != 1 {
		t.Error("didn't get 1 record for the ugly")
	} else if records[0].Password() != "" {
		t.Error("password is defined for the ugly")
	}
}
