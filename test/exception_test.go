package test

import (
	"strings"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestOurException(t *testing.T) {
	// Exceptions the Secrets Manager server will send that have meaning.
	defer func() {
		if r := recover(); r != nil {
			expectedMsg := "POST Error: Error: access_denied, message=Signature is invalid"
			if msg, ok := r.(string); ok && strings.TrimSpace(msg) == expectedMsg {
				t.Log("Received expected error code 403 'Signature is invalid'")
			} else {
				t.Error("did not get correct error message")
			}
		}
	}()
	defer ResetMockResponseQueue()

	rawJson := `
{
	"hostname": "fake.keepersecurity.com",
	"appKey": "8Kx25SvtkRSsEYIur7mHKtLqANFNB7AZRa9cqi2PSQE=",
	"clientId": "45haqPHrK5csKjr2jXJRYrykxaE50QsAR/FR8OiU7aak5LexpGX50/23FJRwNK02thysUBf7AZReQK9q7Q8UUw==",
	"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo=",
	"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU+/LBMQQGfJAycwOtx9djH0YEvBT+hRANCAASB1L44QodSzRaIOhF7f/2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI"
}`
	config := ksm.NewMemoryKeyValueStorage(rawJson)
	sm := ksm.NewSecretsManagerFromConfig(config)

	// Make the error message
	errorJson := `
{
	"path": "https://fake.keepersecurity.com/api/rest/sm/v1/get_secret, POST, Go-http-client/1.1",
	"additional_info": "",
	"location": "default exception manager - api validation exception",
	"error": "access_denied",
	"message": "Signature is invalid"
}`

	MockResponseQueue.AddMockResponse(NewMockResponse([]byte(errorJson), 403, nil))

	if _, err := sm.GetSecrets(nil); err != nil && err.Error() == "Error: access_denied, message=Signature is invalid" {
		t.Log("Received expected error code 403 'Signature is invalid'")
	} else {
		t.Error("did not get correct error message")
	}
}

func TestNotOurException(t *testing.T) {
	// Generic message not specific to the Secrets Manager server.
	defer func() {
		if r := recover(); r != nil {
			expectedMsg := "POST Error: HTTPError: Bad Gateway"
			if msg, ok := r.(string); ok && strings.TrimSpace(msg) == expectedMsg {
				t.Log("Received expected error code 502 'Bad Gateway'")
			} else {
				t.Error("did not get correct error message")
			}
		}
	}()
	defer ResetMockResponseQueue()

	rawJson := `
{
	"hostname": "fake.keepersecurity.com",
	"appKey": "8Kx25SvtkRSsEYIur7mHKtLqANFNB7AZRa9cqi2PSQE=",
	"clientId": "45haqPHrK5csKjr2jXJRYrykxaE50QsAR/FR8OiU7aak5LexpGX50/23FJRwNK02thysUBf7AZReQK9q7Q8UUw==",
	"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo=",
	"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU+/LBMQQGfJAycwOtx9djH0YEvBT+hRANCAASB1L44QodSzRaIOhF7f/2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI"
}`
	config := ksm.NewMemoryKeyValueStorage(rawJson)
	sm := ksm.NewSecretsManagerFromConfig(config)

	MockResponseQueue.AddMockResponse(NewMockResponse([]byte("Bad Gateway"), 502, nil))

	if _, err := sm.GetSecrets(nil); err != nil && err.Error() == "POST Error: HTTPError: Bad Gateway" {
		t.Log("Received expected error code 502 'Bad Gateway'")
	} else {
		t.Error("did not get correct error message")
	}
}

func TestKeyRotation(t *testing.T) {
	// Special exception for rotating the public key.
	defer ResetMockResponseQueue()

	rawJson := `
{
	"hostname": "fake.keepersecurity.com",
	"appKey": "8Kx25SvtkRSsEYIur7mHKtLqANFNB7AZRa9cqi2PSQE=",
	"clientId": "45haqPHrK5csKjr2jXJRYrykxaE50QsAR/FR8OiU7aak5LexpGX50/23FJRwNK02thysUBf7AZReQK9q7Q8UUw==",
	"clientKey": "zKoSCC6eNrd3N9CByRBsdChSsTeDEAMvNj9Bdh7BJuo=",
	"privateKey": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaKWvicgtslVJKJU+/LBMQQGfJAycwOtx9djH0YEvBT+hRANCAASB1L44QodSzRaIOhF7f/2GlM8Fg0R3i3heIhMEdkhcZRDLxIGEeOVi3otS0UBFTrbET6joq0xCjhKMhHQFaHYI"
}`
	config := ksm.NewMemoryKeyValueStorage(rawJson)
	sm := ksm.NewSecretsManagerFromConfig(config, Ctx)

	res1 := NewMockResponse([]byte{}, 200, nil)
	mockRecord1 := res1.AddRecord("My Record", "login", "", nil, nil)
	mockRecord1.Field("login", "", "My Login")
	mockRecord1.Field("password", "", "My Password")

	res2 := NewMockResponse([]byte{}, 200, nil)
	mockRecord2 := res2.AddRecord("My Record", "login", "", nil, nil)
	mockRecord2.Field("login", "", "KEY CHANGE")
	mockRecord2.Field("password", "", "My Password")

	// KEY ROTATION ERROR. error needs to be key.
	errorJson := `
{
	"error": "key",
	"key_id": "8"
}`

	MockResponseQueue.AddMockResponse(res1)
	MockResponseQueue.AddMockResponse(NewMockResponse([]byte(errorJson), 403, nil))
	MockResponseQueue.AddMockResponse(res2)

	records, err := sm.GetSecrets(nil)
	if err != nil || len(records) != 1 {
		t.Error("didn't get 1 records")
	}

	// This one should get a key error, then retry to get record.
	records, err = sm.GetSecrets(nil)
	if err != nil || len(records) != 1 {
		t.Error("didn't get 1 records")
	}
	if sm.Config.Get(ksm.KEY_SERVER_PUBLIC_KEY_ID) != "8" {
		t.Error("didn't get correct key id")
	}
	if mockRecord2.Uid != records[0].Uid {
		t.Error("did not get correct record")
	}
}
