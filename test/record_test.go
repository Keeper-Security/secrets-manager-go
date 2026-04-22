package test

import (
	"encoding/json"
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

// KSM-860: RecordField must serialize with lowercase JSON keys.
// Go's default json.Marshal uses exported field names ("Type", "Label", etc.) unless json struct tags are present.
func TestRecordFieldJsonKeysAreLowercase(t *testing.T) {
	rf := ksm.NewRecordField("login", "", false, []string{"user@example.com"})
	data, err := json.Marshal(rf)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	for _, key := range []string{"type", "label", "value", "required"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing lowercase key %q in serialized RecordField; got: %s", key, data)
		}
	}
}

// KSM-860: NewRecordField must not double-nest []string values.
// Callers pass []string but the type assertion only catches []interface{}, causing [["x"]] instead of ["x"].
func TestRecordFieldValueNotDoubleNested(t *testing.T) {
	rf := ksm.NewRecordField("login", "", false, []string{"user@example.com"})
	if len(rf.Value) != 1 {
		t.Fatalf("expected Value len 1, got %d: %v", len(rf.Value), rf.Value)
	}
	if rf.Value[0] != "user@example.com" {
		t.Errorf("expected Value[0] == \"user@example.com\", got %T %v", rf.Value[0], rf.Value[0])
	}
}

// KSM-756: Records in the flat records[] array that carry a folderUid must be decrypted
// with the folder key, not the app key. The SDK previously used the app key unconditionally,
// causing field values to come back empty for shared-folder records returned in the flat array.
func TestSharedFolderRecordInFlatArray(t *testing.T) {
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	res := NewMockResponse([]byte{}, 200, nil)

	// Shared folder with a distinct key — included in the response so the SDK can
	// look up and decrypt the folder key when processing the flat record.
	folder := res.AddFolder("shared-folder-uid", nil)

	// Flat record: folderUid set, recordKey encrypted with the folder key (not app key).
	flatRecord := NewMockRecord("login", "shared-record-uid", "Shared Record")
	flatRecord.Field("login", "", "", "", "user@example.com")
	flatRecord.Field("password", "", "", "", "s3cr3t")
	flatRecord.FolderUid = folder.Uid
	flatRecord.FolderKey = folder.Key
	res.Records[flatRecord.Uid] = flatRecord

	MockResponseQueue.AddMockResponse(res)

	records, err := sm.GetSecrets([]string{})
	if err != nil {
		t.Fatalf("GetSecrets failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if login := r.GetFieldValueByType("login"); login != "user@example.com" {
		t.Errorf("expected login 'user@example.com', got %q", login)
	}
	if pass := r.GetFieldValueByType("password"); pass != "s3cr3t" {
		t.Errorf("expected password 's3cr3t', got %q", pass)
	}
	if r.FolderUid() != "shared-folder-uid" {
		t.Errorf("expected folderUid 'shared-folder-uid', got %q", r.FolderUid())
	}
}

// KSM-826: RecordCreate.ToDict() must always include "custom" key, even when empty.
// Commander and Vault always send "custom": [] and the backend expects it present.
func TestRecordCreateToDictAlwaysIncludesCustom(t *testing.T) {
	rc := ksm.NewRecordCreate("login", "Test Record")
	// Custom is empty (default)
	dict := rc.ToDict()
	if _, ok := dict["custom"]; !ok {
		t.Error("ToDict() missing 'custom' key when Custom is empty")
	}
}

// KSM-911: GetSecrets must skip records whose AES-GCM data decryption fails.
// Before this fix, a failed decryption produced an empty record stub appended to the result.
func TestDecryptionFailureSkipsRecord(t *testing.T) {
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	res := NewMockResponse([]byte{}, 200, nil)

	// Good record — decrypts normally.
	res.AddRecord("Good Record", "login", "good-uid", nil, nil)

	// Bad record — data is random bytes so AES-GCM authentication fails.
	bad := NewMockRecord("login", "bad-uid", "Bad Record")
	bad.CorruptData = true
	res.Records[bad.Uid] = bad

	MockResponseQueue.AddMockResponse(res)

	records, err := sm.GetSecrets([]string{})
	if err != nil {
		t.Fatalf("GetSecrets returned unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 record (bad record should be skipped), got %d", len(records))
	}
	if len(records) == 1 && records[0].Uid != "good-uid" {
		t.Errorf("expected good-uid record, got %q", records[0].Uid)
	}
}

// KSM-911: GetSecrets must skip records whose AES-GCM key decryption fails.
// A corrupted recordKey means RecordKeyBytes is never set; previously the record
// was silently returned as a stub with no field data.
func TestKeyDecryptionFailureSkipsRecord(t *testing.T) {
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	res := NewMockResponse([]byte{}, 200, nil)

	// Good record — decrypts normally.
	res.AddRecord("Good Record", "login", "good-uid", nil, nil)

	// Bad record — recordKey is random bytes so key decryption fails before data is attempted.
	bad := NewMockRecord("login", "bad-key-uid", "Bad Key Record")
	bad.CorruptKey = true
	res.Records[bad.Uid] = bad

	MockResponseQueue.AddMockResponse(res)

	records, err := sm.GetSecrets([]string{})
	if err != nil {
		t.Fatalf("GetSecrets returned unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 record (bad-key record should be skipped), got %d", len(records))
	}
	if len(records) == 1 && records[0].Uid != "good-uid" {
		t.Errorf("expected good-uid record, got %q", records[0].Uid)
	}
}

// KSM-911: GetSecrets must skip both corrupted-key and corrupted-data records,
// returning only the healthy records from a mixed response.
func TestMixedDecryptionFailuresSkipBadRecords(t *testing.T) {
	defer ResetMockResponseQueue()

	configJson := MockConfig{}.MakeJson(MockConfig{}.MakeConfig(nil, "", "", ""))
	config := ksm.NewMemoryKeyValueStorage(configJson)
	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: config}, Ctx)

	res := NewMockResponse([]byte{}, 200, nil)

	res.AddRecord("Good Record 1", "login", "good-1", nil, nil)
	res.AddRecord("Good Record 2", "login", "good-2", nil, nil)

	badData := NewMockRecord("login", "bad-data", "Bad Data")
	badData.CorruptData = true
	res.Records[badData.Uid] = badData

	badKey := NewMockRecord("login", "bad-key", "Bad Key")
	badKey.CorruptKey = true
	res.Records[badKey.Uid] = badKey

	MockResponseQueue.AddMockResponse(res)

	records, err := sm.GetSecrets([]string{})
	if err != nil {
		t.Fatalf("GetSecrets returned unexpected error: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("expected 2 records (both bad records should be skipped), got %d", len(records))
	}
	for _, r := range records {
		if r.Uid != "good-1" && r.Uid != "good-2" {
			t.Errorf("unexpected record in result: %q", r.Uid)
		}
	}
}
