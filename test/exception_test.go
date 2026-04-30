package test

import (
	"errors"
	"strings"
	"testing"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

func TestOurException(t *testing.T) {
	// Exceptions the Secrets Manager server will send that have meaning.
	defer func() {
		if r := recover(); r != nil {
			expectedMsg := "POST Error: HTTPStatus=403 Error: access_denied, message=Signature is invalid"
			if msg, ok := r.(string); ok && strings.TrimSpace(msg) == expectedMsg {
				t.Log("Received expected error code 403 'Signature is invalid'")
			} else {
				t.Error("did not get correct error message")
			}
		}
	}()
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

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

	_, err := sm.GetSecrets(nil)
	expectedMsg := "POST Error: HTTPStatus=403 Error: access_denied, message=Signature is invalid"
	if err == nil || err.Error() != expectedMsg {
		t.Errorf("wrong error message: got %q, want %q", err, expectedMsg)
		return
	}
	t.Log("Received expected error code 403 'Signature is invalid'")

	// Verify errors.As exposes the structured fields.
	var khe *ksm.KeeperHTTPError
	if !errors.As(err, &khe) {
		t.Error("errors.As did not find *KeeperHTTPError in chain")
		return
	}
	if khe.StatusCode != 403 {
		t.Errorf("KeeperHTTPError.StatusCode = %d, want 403", khe.StatusCode)
	}
	if khe.ResultCode != "access_denied" {
		t.Errorf("KeeperHTTPError.ResultCode = %q, want %q", khe.ResultCode, "access_denied")
	}
	if khe.Message != "Signature is invalid" {
		t.Errorf("KeeperHTTPError.Message = %q, want %q", khe.Message, "Signature is invalid")
	}
}

func TestNotOurException(t *testing.T) {
	// Generic message not specific to the Secrets Manager server.
	defer func() {
		if r := recover(); r != nil {
			expectedMsg := "POST Error: HTTPStatus=502 HTTPError: Bad Gateway"
			if msg, ok := r.(string); ok && strings.TrimSpace(msg) == expectedMsg {
				t.Log("Received expected error code 502 'Bad Gateway'")
			} else {
				t.Error("did not get correct error message")
			}
		}
	}()
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	MockResponseQueue.AddMockResponse(NewMockResponse([]byte("Bad Gateway"), 502, nil))

	_, err := sm.GetSecrets(nil)
	expectedMsg := "POST Error: HTTPStatus=502 HTTPError: Bad Gateway"
	if err == nil || err.Error() != expectedMsg {
		t.Errorf("wrong error message: got %q, want %q", err, expectedMsg)
		return
	}
	t.Log("Received expected error code 502 'Bad Gateway'")

	// Verify errors.As exposes the structured fields.
	var khe *ksm.KeeperHTTPError
	if !errors.As(err, &khe) {
		t.Error("errors.As did not find *KeeperHTTPError in chain")
		return
	}
	if khe.StatusCode != 502 {
		t.Errorf("KeeperHTTPError.StatusCode = %d, want 502", khe.StatusCode)
	}
	if khe.ResultCode != "" {
		t.Errorf("KeeperHTTPError.ResultCode = %q, want empty (non-JSON body)", khe.ResultCode)
	}
	if string(khe.Body) != "Bad Gateway" {
		t.Errorf("KeeperHTTPError.Body = %q, want %q", string(khe.Body), "Bad Gateway")
	}
}

func TestHTTPErrorErrorsAs(t *testing.T) {
	// Verify that a 429 JSON-error response produces a KeeperHTTPError with the correct status code.
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	errorJson := `{"error": "throttled", "message": "too many requests"}`
	MockResponseQueue.AddMockResponse(NewMockResponse([]byte(errorJson), 429, nil))

	_, err := sm.GetSecrets(nil)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	var khe *ksm.KeeperHTTPError
	if !errors.As(err, &khe) {
		t.Fatalf("errors.As did not find *KeeperHTTPError: %v", err)
	}
	if khe.StatusCode != 429 {
		t.Errorf("KeeperHTTPError.StatusCode = %d, want 429", khe.StatusCode)
	}
	if khe.ResultCode != "throttled" {
		t.Errorf("KeeperHTTPError.ResultCode = %q, want %q", khe.ResultCode, "throttled")
	}
	if khe.Message != "too many requests" {
		t.Errorf("KeeperHTTPError.Message = %q, want %q", khe.Message, "too many requests")
	}
	if !strings.Contains(err.Error(), "HTTPStatus=429") {
		t.Errorf("error string %q should contain HTTPStatus=429", err.Error())
	}
}

func TestKeyRotation(t *testing.T) {
	// Special exception for rotating the public key.
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	res1 := NewMockResponse([]byte{}, 200, nil)
	mockRecord1 := res1.AddRecord("My Record", "login", "", nil, nil)
	mockRecord1.Field("login", "", "", "", "My Login")
	mockRecord1.Field("password", "", "", "", "My Password")

	res2 := NewMockResponse([]byte{}, 200, nil)
	mockRecord2 := res2.AddRecord("My Record", "login", "", nil, nil)
	mockRecord2.Field("login", "", "", "", "KEY CHANGE")
	mockRecord2.Field("password", "", "", "", "My Password")

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
