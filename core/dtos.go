package core

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

type FieldSectionFlag byte

const (
	FieldSectionFields FieldSectionFlag = 1 << iota
	FieldSectionCustom
	FieldSectionBoth = FieldSectionFields | FieldSectionCustom
)

type FieldTokenFlag byte

const (
	FieldTokenType FieldTokenFlag = 1 << iota
	FieldTokenLabel
)

type Record struct {
	RecordKeyBytes []byte
	Uid            string
	folderKeyBytes []byte
	folderUid      string
	Files          []*KeeperFile
	Revision       int64
	IsEditable     bool
	recordType     string
	RawJson        string
	RecordDict     map[string]interface{}
}

func (r *Record) FolderUid() string {
	return r.folderUid
}

func (r *Record) Password() string {
	password := ""
	// password (if `login` type)
	if r.Type() == "login" {
		password = r.GetFieldValueByType("password")
	}
	return password
}

func (r *Record) SetPassword(password string) {
	if passwordFields := r.GetFieldsByType("password"); len(passwordFields) > 0 {
		passwordField := passwordFields[0]
		if vlist, ok := passwordField["value"].([]interface{}); ok && len(vlist) > 0 {
			if _, ok := vlist[0].(string); ok {
				vlist[0] = password
			} else {
				klog.Error("error changing password - expected string value")
			}
		} else {
			passwordField["value"] = []string{password}
		}

	} else {
		klog.Error("password field not found for UID: " + r.Uid)
	}
}

func (r *Record) SetFieldValueSingle(fieldType, value string) {
	if fields := r.GetFieldsByType(fieldType); len(fields) > 0 {
		field := fields[0]
		if vlist, ok := field["value"].([]interface{}); ok && len(vlist) > 0 {
			if _, ok := vlist[0].(string); ok {
				vlist[0] = value
			} else {
				klog.Error("error changing field value - expected string value")
			}
		} else {
			field["value"] = []string{value}
		}

	} else {
		klog.Error("field not found for UID: " + r.Uid)
	}
}

func (r *Record) SetCustomFieldValueSingle(fieldLabel, value string) {
	if fields := r.GetCustomFieldsByLabel(fieldLabel); len(fields) > 0 {
		field := fields[0]
		if vlist, ok := field["value"].([]interface{}); ok && len(vlist) > 0 {
			if _, ok := vlist[0].(string); ok {
				vlist[0] = value
			} else {
				klog.Error("error changing custom field value - expected string value")
			}
		} else {
			field["value"] = []string{value}
		}

	} else {
		klog.Error("custom field not found for UID: " + r.Uid)
	}
}

func (r *Record) Title() string {
	if recordTitle, ok := r.RecordDict["title"].(string); ok {
		return recordTitle
	}
	return ""
}

func (r *Record) SetTitle(title string) {
	if _, ok := r.RecordDict["title"]; ok {
		r.RecordDict["title"] = title
	}
}

func (r *Record) Type() string {
	if recordType, ok := r.RecordDict["type"].(string); ok {
		return recordType
	}
	return ""
}

func (r *Record) SetType(newType string) {
	klog.Error("Change Type not allowed!") // not implemented
}

func (r *Record) Notes() string {
	if recordNotes, ok := r.RecordDict["notes"].(string); ok {
		return recordNotes
	}
	return ""
}

func (r *Record) SetNotes(notes string) {
	if _, ok := r.RecordDict["notes"]; ok {
		r.RecordDict["notes"] = notes
	}
}

func (r *Record) GetFieldsByMask(fieldToken string, fieldTokenFlag FieldTokenFlag, fieldType FieldSectionFlag) []map[string]interface{} {
	result := []map[string]interface{}{}

	if fieldToken == "" {
		return result
	}

	fields := []interface{}{}
	if fieldType&FieldSectionFields == FieldSectionFields {
		if iFields, ok := r.RecordDict["fields"]; ok {
			if aFields, ok := iFields.([]interface{}); ok {
				fields = append(fields, aFields...)
			}
		}
	}

	if fieldType&FieldSectionCustom == FieldSectionCustom {
		if iFields, ok := r.RecordDict["custom"]; ok {
			if aFields, ok := iFields.([]interface{}); ok {
				fields = append(fields, aFields...)
			}
		}
	}

	for i := range fields {
		if fmap, ok := fields[i].(map[string]interface{}); ok {
			val := map[string]interface{}{}
			if fieldTokenFlag&FieldTokenType == FieldTokenType {
				if fType, ok := fmap["type"].(string); ok && fType == fieldToken {
					val = fmap
				}
			}
			if len(val) == 0 && fieldTokenFlag&FieldTokenLabel == FieldTokenLabel {
				if fLabel, ok := fmap["label"].(string); ok && fLabel == fieldToken {
					val = fmap
				}
			}
			if len(val) > 0 {
				result = append(result, val)
			}
		}
	}

	return result
}

func (r *Record) GetFieldsByType(fieldType string) []map[string]interface{} {
	return r.GetFieldsByMask(fieldType, FieldTokenType, FieldSectionFields)
}

func (r *Record) GetFieldsByLabel(fieldLabel string) []map[string]interface{} {
	return r.GetFieldsByMask(fieldLabel, FieldTokenLabel, FieldSectionFields)
}

func (r *Record) GetCustomFieldsByType(fieldType string) []map[string]interface{} {
	return r.GetFieldsByMask(fieldType, FieldTokenType, FieldSectionCustom)
}

func (r *Record) GetCustomFieldsByLabel(fieldLabel string) []map[string]interface{} {
	return r.GetFieldsByMask(fieldLabel, FieldTokenLabel, FieldSectionCustom)
}

// GetFieldValueByType returns string value of the *first* field from fields[] that matches fieldType
func (r *Record) GetFieldValueByType(fieldType string) string {
	if fieldType == "" {
		return ""
	}

	values := []string{}
	if fields := r.GetFieldsByType(fieldType); len(fields) > 0 {
		if iValues, ok := fields[0]["value"].([]interface{}); ok {
			for i := range iValues {
				val := iValues[i]
				// JavaScript has no integers but only one number type, IEEE754 double precision float
				if fval, ok := val.(float64); ok && fval == float64(int(fval)) {
					val = int(fval) // convert to int
				}
				values = append(values, fmt.Sprintf("%v", val))
			}
		}
	}

	return strings.Join(values, ", ")
}

// GetFieldValueByLabel returns string value of the *first* field from fields[] that matches fieldLabel
func (r *Record) GetFieldValueByLabel(fieldLabel string) string {
	if fieldLabel == "" {
		return ""
	}

	values := []string{}
	if fields := r.GetFieldsByLabel(fieldLabel); len(fields) > 0 {
		if iValues, ok := fields[0]["value"].([]interface{}); ok {
			for i := range iValues {
				values = append(values, fmt.Sprintf("%v", iValues[i]))
			}
		}
	}

	return strings.Join(values, ", ")
}

func (r *Record) GetFieldValuesByType(fieldType string) []string {
	values := []string{}
	if fieldType == "" {
		return values
	}

	if fields := r.GetFieldsByType(fieldType); len(fields) > 0 {
		if iValues, ok := fields[0]["value"].([]interface{}); ok {
			for i := range iValues {
				values = append(values, fmt.Sprintf("%v", iValues[i]))
			}
		}
	}

	return values
}

func (r *Record) GetCustomFieldValues(label string, fieldType string) []string {
	values := []string{}
	if label == "" && fieldType == "" {
		return values
	}

	fields := []map[string]interface{}{}
	if fieldType != "" {
		if flds := r.GetCustomFieldsByType(fieldType); len(flds) > 0 {
			for _, fld := range flds {
				if iLabel, ok := fld["label"].(string); label == "" || (ok && label == iLabel) {
					fields = append(fields, fld)
				}
			}
		}
	} else if label != "" {
		if flds := r.GetCustomFieldsByLabel(label); len(flds) > 0 {
			for _, fld := range flds {
				if iType, ok := fld["type"].(string); fieldType == "" || (ok && fieldType == iType) {
					fields = append(fields, fld)
				}
			}
		}
	}

	for _, field := range fields {
		if iValues, ok := field["value"].([]interface{}); ok {
			for i := range iValues {
				values = append(values, fmt.Sprintf("%v", iValues[i]))
			}
		}
	}

	return values
}

// GetCustomFieldValueByType returns string value of the *first* field from custom[] that matches fieldType
func (r *Record) GetCustomFieldValueByType(fieldType string) string {
	if fieldType == "" {
		return ""
	}

	values := []string{}
	if fields := r.GetCustomFieldsByType(fieldType); len(fields) > 0 {
		if iValues, ok := fields[0]["value"].([]interface{}); ok {
			for i := range iValues {
				values = append(values, fmt.Sprintf("%v", iValues[i]))
			}
		}
	}

	result := ""
	if len(values) == 1 {
		result = values[0]
	} else if len(values) > 1 {
		result = strings.Join(values, ", ")
	}
	return result
}

// GetCustomFieldValueByLabel returns string value of the *first* field from custom[] that matches fieldLabel
func (r *Record) GetCustomFieldValueByLabel(fieldLabel string) string {
	if fieldLabel == "" {
		return ""
	}

	values := []string{}
	if fields := r.GetCustomFieldsByLabel(fieldLabel); len(fields) > 0 {
		if iValues, ok := fields[0]["value"].([]interface{}); ok {
			for i := range iValues {
				values = append(values, fmt.Sprintf("%v", iValues[i]))
			}
		}
	}

	result := ""
	if len(values) == 1 {
		result = values[0]
	} else if len(values) > 1 {
		result = strings.Join(values, ", ")
	}
	return result
}

func NewRecordFromJson(recordDict map[string]interface{}, secretKey []byte, folderUid string) *Record {
	record := Record{}

	// if folderUid is present then secretKey is the folder key
	// if folderUid is empty then record is directly shared to the app and secretKey is the app key
	if strings.TrimSpace(folderUid) != "" {
		record.folderUid = folderUid
		record.folderKeyBytes = secretKey
	}

	if uid, ok := recordDict["recordUid"]; ok {
		record.Uid = strings.TrimSpace(uid.(string))
	}
	if revision, ok := recordDict["revision"].(float64); ok {
		record.Revision = int64(revision)
	}
	if isEditable, ok := recordDict["isEditable"].(bool); ok {
		record.IsEditable = isEditable
	}

	recordKeyEncryptedStr := ""
	if recKey, ok := recordDict["recordKey"]; ok {
		recordKeyEncryptedStr = strings.TrimSpace(recKey.(string))
	}

	if recordKeyEncryptedStr != "" {
		//Folder Share
		recordKeyEncryptedBytes := Base64ToBytes(recordKeyEncryptedStr)
		if recordKeyBytes, err := Decrypt(recordKeyEncryptedBytes, secretKey); err == nil {
			record.RecordKeyBytes = recordKeyBytes
		} else {
			klog.Error("error decrypting record key: " + err.Error() + " - Record UID: " + record.Uid)
		}
	} else {
		//Single Record Share
		record.RecordKeyBytes = secretKey
	}

	if recordEncryptedData, ok := recordDict["data"]; ok && len(record.RecordKeyBytes) > 0 {
		strRecordEncryptedData := recordEncryptedData.(string)
		if recordDataJson, err := DecryptRecord(Base64ToBytes(strRecordEncryptedData), record.RecordKeyBytes); err == nil {
			record.RawJson = recordDataJson
			record.RecordDict = JsonToDict(record.RawJson)
		} else {
			klog.Error("error decrypting record data: " + err.Error())
		}
	}

	if recordType, ok := record.RecordDict["type"]; ok {
		record.recordType = recordType.(string)
	}

	// files
	if recordFiles, ok := recordDict["files"]; ok {
		if rfSlice, ok := recordFiles.([]interface{}); ok {
			for i := range rfSlice {
				if rfMap, ok := rfSlice[i].(map[string]interface{}); ok {
					if file := NewKeeperFileFromJson(rfMap, record.RecordKeyBytes); file != nil {
						record.Files = append(record.Files, file)
					}
				}
			}
		}
	}

	return &record
}

// FindFileByTitle finds file by file title
func (r *Record) FindFileByTitle(title string) *KeeperFile {
	for i := range r.Files {
		if r.Files[i].Title == title {
			return r.Files[i]
		}
	}
	return nil
}

func (r *Record) DownloadFileByTitle(title string, path string) bool {
	if foundFile := r.FindFileByTitle(title); foundFile != nil {
		return foundFile.SaveFile(path, false)
	}
	return false
}

func (r *Record) ToString() string {
	return fmt.Sprintf("[Record: UID=%s, revision=%d, editable=%t, type: %s, title: %s, files count: %d]", r.Uid, r.Revision, r.IsEditable, r.recordType, r.Title(), len(r.Files))
}

func (r *Record) Update() {
	// Record class works directly on fields in recordDict here we only update the raw JSON
	r.RawJson = DictToJson(r.RecordDict)
}

func (r *Record) value(values []interface{}, single bool) []interface{} {
	if len(values) == 0 {
		return []interface{}{}
	}
	if single {
		return []interface{}{values[0]}
	}
	return values
}

func (r *Record) fieldSearch(fields []interface{}, fieldKey string) map[string]interface{} {
	// This is a generic field search that returns the field
	// It will work for for both standard and custom fields.
	// It returns the field as a map[string]interface{}.

	foundItem := map[string]interface{}{}
	if len(fields) == 0 {
		return foundItem
	}

	// First check in the field_key matches any labels. Label matching is case sensitive.
	for _, item := range fields {
		if iValue, ok := item.(map[string]interface{}); ok {
			if iLabel, found := iValue["label"]; found {
				if sLabel, ok := iLabel.(string); ok && strings.EqualFold(sLabel, fieldKey) {
					foundItem = iValue
					break
				}
			}
		}
	}
	// If the label was not found, check the field type. Field type is case insensitive.
	if len(foundItem) == 0 {
		for _, item := range fields {
			if iValue, ok := item.(map[string]interface{}); ok {
				if iType, found := iValue["type"]; found {
					if sType, ok := iType.(string); ok && strings.EqualFold(sType, fieldKey) {
						foundItem = iValue
						break
					}
				}
			}
		}
	}
	return foundItem
}

func (r *Record) getStandardField(fieldType string) map[string]interface{} {
	if iFields, found := r.RecordDict["fields"]; found {
		if sFields, ok := iFields.([]interface{}); ok {
			return r.fieldSearch(sFields, fieldType)
		}
	}
	return map[string]interface{}{}
}

func (r *Record) GetStandardFieldValue(fieldType string, single bool) ([]interface{}, error) {
	field := r.getStandardField(fieldType)
	if len(field) == 0 {
		return nil, fmt.Errorf("cannot find standard field %s in record", fieldType)
	}
	sValue := []interface{}{}
	if iValue, found := field["value"]; found {
		if sVal, ok := iValue.([]interface{}); ok {
			sValue = sVal
		}
	}
	return r.value(sValue, single), nil
}

func (r *Record) SetStandardFieldValue(fieldType string, value interface{}) error {
	field := r.getStandardField(fieldType)
	if len(field) == 0 {
		return fmt.Errorf("cannot find standard field %s in record", fieldType)
	}
	if _, ok := value.([]interface{}); !ok {
		value = []interface{}{value}
	}
	field["value"] = value
	r.Update()
	return nil
}

func (r *Record) getCustomField(fieldType string) map[string]interface{} {
	if iFields, found := r.RecordDict["custom"]; found {
		if sFields, ok := iFields.([]interface{}); ok {
			return r.fieldSearch(sFields, fieldType)
		}
	}
	return map[string]interface{}{}
}

func (r *Record) GetCustomFieldValue(fieldType string, single bool) ([]interface{}, error) {
	field := r.getCustomField(fieldType)
	if len(field) == 0 {
		return nil, fmt.Errorf("cannot find custom field %s in record", fieldType)
	}
	sValue := []interface{}{}
	if iValue, found := field["value"]; found {
		if sVal, ok := iValue.([]interface{}); ok {
			sValue = sVal
		}
	}
	return r.value(sValue, single), nil
}

func (r *Record) SetCustomFieldValue(fieldType string, value interface{}) error {
	field := r.getCustomField(fieldType)
	if len(field) == 0 {
		return fmt.Errorf("cannot find custom field %s in record", fieldType)
	}
	if _, ok := value.([]interface{}); !ok {
		value = []interface{}{value}
	}
	field["value"] = value
	r.Update()
	return nil
}

func (r *Record) CanClone() bool {
	if strings.TrimSpace(r.folderUid) != "" && len(r.folderKeyBytes) > 0 {
		return true
	} else {
		return false
	}
}

func findTemplateRecord(templateRecordUid string, records []*Record) (*Record, error) {
	var templateRecord *Record = nil

	for _, r := range records {
		if r.Uid == templateRecordUid {
			templateRecord = r
			if strings.TrimSpace(r.folderUid) != "" && len(r.folderKeyBytes) > 0 {
				break
			}
		}
	}

	if templateRecord == nil {
		return nil, fmt.Errorf("cannot find template record '%s' in record", templateRecordUid)
	}

	// Records shared directly to the application cannot be used as template records
	// only records in a shared folder (shared to the application) should be used as templates
	if strings.TrimSpace(templateRecord.folderUid) == "" || len(templateRecord.folderKeyBytes) == 0 {
		return nil, fmt.Errorf("found matching template record %s which is not in a shared folder", templateRecordUid)
	}

	return templateRecord, nil
}

// NewRecordClone returns a deep copy of the template object with new UID and RecordKeyBytes
// generates and uses new random UID if newRecordUid is empty
// returns error if template record is not found
func NewRecordClone(templateRecordUid string, records []*Record, newRecordUid string) (*Record, error) {
	templateRecord, err := findTemplateRecord(templateRecordUid, records)
	if err != nil {
		return nil, err
	}

	recordKeyBytes, _ := GetRandomBytes(32)
	folderKeyBytesCopy := make([]byte, len(templateRecord.folderKeyBytes))
	copy(folderKeyBytesCopy, templateRecord.folderKeyBytes)
	recordDictCopy := CopyableMap(templateRecord.RecordDict).DeepCopy()

	filesCopy := []*KeeperFile{}
	for _, f := range templateRecord.Files {
		filesCopy = append(filesCopy, f.DeepCopy())
	}

	recordUid := GenerateUid()
	if ruid := strings.TrimSpace(newRecordUid); ruid != "" {
		if numBytes := len(Base64ToBytes(ruid)); numBytes == 16 {
			recordUid = newRecordUid
		}
	}
	if newRecordUid != "" && recordUid != newRecordUid {
		klog.Warning("invalid new record UID provided:", newRecordUid, " - using autogenerated UID:", recordUid)
	}

	rec := &Record{
		RecordKeyBytes: recordKeyBytes,
		Uid:            recordUid,
		folderKeyBytes: folderKeyBytesCopy,
		folderUid:      templateRecord.folderUid,
		Files:          filesCopy,
		Revision:       templateRecord.Revision,
		IsEditable:     templateRecord.IsEditable,
		recordType:     templateRecord.recordType,
		RawJson:        templateRecord.RawJson,
		RecordDict:     recordDictCopy,
	}

	return rec, nil
}

// NewRecord returns a new empty record of the same type as template object but with new UID and RecordKeyBytes
// generates and uses new random UID if newRecordUid is empty
// returns error if template record is not found
func NewRecord(templateRecordUid string, records []*Record, newRecordUid string) (*Record, error) {
	templateRecord, err := findTemplateRecord(templateRecordUid, records)
	if err != nil {
		return nil, err
	}

	recordKeyBytes, _ := GetRandomBytes(32)
	folderKeyBytesCopy := make([]byte, len(templateRecord.folderKeyBytes))
	copy(folderKeyBytesCopy, templateRecord.folderKeyBytes)

	// copy and preserve known keys but clear all other values except record type
	// drop custom[] and any other unknown top-level keys
	recordDictCopy := CopyableMap(templateRecord.RecordDict).DeepCopy()
	for key, val := range recordDictCopy {
		switch key {
		case "type":
			continue
		case "title", "notes":
			recordDictCopy[key] = ""
		case "custom":
			delete(recordDictCopy, key)
		case "fields":
			if fslice, ok := val.([]interface{}); ok {
				for _, fs := range fslice {
					if fmap, ok := fs.(map[string]interface{}); ok {
						for fkey := range fmap {
							// preserve field type, clear label and value, drop everything else
							switch fkey {
							case "type":
								continue
							case "label":
								fmap[fkey] = ""
							case "value":
								fmap[fkey] = []interface{}{}
							default:
								klog.Warning("create new record - removing field type property", key)
								delete(fmap, key)
							}
						}
					} else {
						klog.Warning("create new record - fields type is not in the expected format and is removed")
					}
				}
			} else {
				klog.Warning("create new record - fields[] is not in the expected format and is replaced")
				recordDictCopy[key] = []interface{}{}
			}
		default:
			klog.Warning("create new record - removing unknown record type property", key)
			delete(recordDictCopy, key)
		}
	}
	rawJson := DictToJson(recordDictCopy)

	recordUid := GenerateUid()
	if ruid := strings.TrimSpace(newRecordUid); ruid != "" {
		if numBytes := len(Base64ToBytes(ruid)); numBytes == 16 {
			recordUid = newRecordUid
		}
	}
	if newRecordUid != "" && recordUid != newRecordUid {
		klog.Warning("invalid new record UID provided:", newRecordUid, " - using autogenerated UID:", recordUid)
	}

	rec := &Record{
		RecordKeyBytes: recordKeyBytes,
		Uid:            recordUid,
		folderKeyBytes: folderKeyBytesCopy,
		folderUid:      templateRecord.folderUid,
		Files:          []*KeeperFile{},
		Revision:       templateRecord.Revision,
		IsEditable:     templateRecord.IsEditable,
		recordType:     templateRecord.recordType,
		RawJson:        rawJson,
		RecordDict:     recordDictCopy,
	}

	return rec, nil
}

func (r *Record) Print() {
	fmt.Println("===")
	fmt.Println("Title: " + r.Title())
	fmt.Println("UID:   " + r.Uid)
	fmt.Println("Type:  " + r.Type())

	fmt.Println()
	fmt.Println("Fields")
	fmt.Println("------")
	skipFileds := map[string]struct{}{"fileRef": {}, "oneTimeCode": {}}
	if _fields, ok := r.RecordDict["fields"]; ok {
		if fields, ok := _fields.([]interface{}); ok {
			for i := range fields {
				if fmap, ok := fields[i].(map[string]interface{}); ok {
					ftype, _ := fmap["type"].(string)
					// flabel, _ := fmap["label"].(string)
					if _, found := skipFileds[ftype]; !found {
						fmt.Printf("%s : %v\n", ftype, fmap["value"]) // ", ".join(item["value"]
					}
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("Custom Fields")
	fmt.Println("------")
	if _fields, ok := r.RecordDict["custom"]; ok {
		if fields, ok := _fields.([]interface{}); ok {
			for i := range fields {
				if fmap, ok := fields[i].(map[string]interface{}); ok {
					ftype, _ := fmap["type"].(string)
					flabel, _ := fmap["label"].(string)
					fmt.Printf("%s (%s) : %v\n", ftype, flabel, fmap["value"]) // ", ".join(item["value"]
				}
			}
		}
	}
}

type Folder struct {
	uid           string
	folderKey     []byte
	data          map[string]interface{}
	folderRecords []map[string]interface{}
}

func NewFolderFromJson(folderDict map[string]interface{}, secretKey []byte) *Folder {
	folder := Folder{
		data: folderDict,
	}
	if uid, ok := folderDict["folderUid"]; ok {
		folder.uid = strings.TrimSpace(uid.(string))
		if folderKeyEnc, ok := folderDict["folderKey"]; ok {
			if folderKey, err := Decrypt(Base64ToBytes(folderKeyEnc.(string)), secretKey); err == nil {
				folder.folderKey = folderKey
				if folderRecords, ok := folderDict["records"]; ok {
					if iFolderRecords, ok := folderRecords.([]interface{}); ok {
						for i := range iFolderRecords {
							if folderRecord, ok := iFolderRecords[i].(map[string]interface{}); ok {
								folder.folderRecords = append(folder.folderRecords, folderRecord)
							}
						}
					} else {
						klog.Error("folder records JSON is in incorrect format")
					}
				}
			} else {
				klog.Error("error decrypting folder key: " + err.Error())
			}
		}
	} else {
		klog.Error("Not a folder")
		return nil
	}

	return &folder
}

func (f *Folder) Records() []*Record {
	records := []*Record{}
	if f.folderRecords != nil {
		for _, r := range f.folderRecords {
			if record := NewRecordFromJson(r, f.folderKey, f.uid); record.Uid != "" {
				records = append(records, record)
			} else {
				klog.Error("error parsing folder record: ", r)
			}
		}
	}
	return records
}

type KeeperFile struct {
	FileKey  string
	metaDict map[string]interface{}

	FileData []byte

	Uid          string
	Type         string
	Title        string
	Name         string
	LastModified int
	Size         int

	F              map[string]interface{}
	RecordKeyBytes []byte
}

func NewKeeperFileFromJson(fileDict map[string]interface{}, recordKeyBytes []byte) *KeeperFile {
	f := &KeeperFile{
		F:              fileDict,
		RecordKeyBytes: recordKeyBytes,
	}

	// Set file metadata
	meta := f.GetMeta()

	if fuid, ok := fileDict["fileUid"].(string); ok {
		f.Uid = fuid
	}
	if recordType, ok := meta["type"].(string); ok {
		f.Type = recordType
	}
	if title, ok := meta["title"].(string); ok {
		f.Title = title
	}
	if name, ok := meta["name"].(string); ok {
		f.Name = name
	}
	if lastModified, ok := meta["lastModified"].(float64); ok {
		f.LastModified = int(lastModified)
	}
	if size, ok := meta["size"].(float64); ok {
		f.Size = int(size)
	}

	return f
}

func (f *KeeperFile) DeepCopy() *KeeperFile {
	return &KeeperFile{
		FileKey:        f.FileKey,
		metaDict:       CopyableMap(f.metaDict).DeepCopy(),
		FileData:       CloneByteSlice(f.FileData),
		Uid:            f.Uid,
		Type:           f.Type,
		Title:          f.Title,
		Name:           f.Name,
		LastModified:   f.LastModified,
		Size:           f.Size,
		F:              CopyableMap(f.F).DeepCopy(),
		RecordKeyBytes: CloneByteSlice(f.RecordKeyBytes),
	}
}

func (f *KeeperFile) DecryptFileKey() []byte {
	fileKeyEncryptedBase64 := f.F["fileKey"]
	fileKeyEncryptedBase64Str := fmt.Sprintf("%v", fileKeyEncryptedBase64)
	fileKeyEncrypted := Base64ToBytes(fileKeyEncryptedBase64Str)
	if fileKey, err := Decrypt(fileKeyEncrypted, f.RecordKeyBytes); err == nil {
		return fileKey
	} else {
		klog.Error("error decrypting file key " + fileKeyEncryptedBase64Str)
		return []byte{}
	}
}

func (f *KeeperFile) GetMeta() map[string]interface{} {
	// Returns file metadata dictionary (file name, title, size, type, etc.)
	if len(f.metaDict) == 0 {
		if data, ok := f.F["data"]; ok && data != nil {
			fileKey := f.DecryptFileKey()
			dataStr := fmt.Sprintf("%v", data)
			if metaJson, err := Decrypt(Base64ToBytes(dataStr), fileKey); err == nil {
				f.metaDict = JsonToDict(string(metaJson[:]))
			} else {
				klog.Error("error parsing file meta data " + dataStr)
			}
		}
	}
	return f.metaDict
}

func (f *KeeperFile) GetUrl() string {
	if url, ok := f.F["url"].(string); ok {
		return url
	}
	return ""
}

func (f *KeeperFile) GetFileData() []byte {
	// Return decrypted raw file data
	if len(f.FileData) == 0 { // cached if nothing
		fileKey := f.DecryptFileKey()
		if fileUrl, ok := f.F["url"]; ok && fileUrl != nil {
			fileUrlStr := fmt.Sprintf("%v", fileUrl)
			if rs, err := http.Get(fileUrlStr); err == nil {
				defer rs.Body.Close()
				if fileEncryptedData, err := ioutil.ReadAll(rs.Body); err == nil {
					if fileData, err := Decrypt(fileEncryptedData, fileKey); err == nil {
						f.FileData = fileData
					}
				}
			}
		}
	}
	return f.FileData
}

func (f *KeeperFile) SaveFile(path string, createFolders bool) bool {
	// Save decrypted file data to the provided path
	if createFolders {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			klog.Error("error creating folders " + err.Error())
		}
	}

	pathExists := false
	if absPath, err := filepath.Abs(path); err == nil {
		dirPath := filepath.Dir(absPath)
		if found, _ := PathExists(dirPath); found {
			pathExists = true
		}
	}

	if !pathExists {
		klog.Error("No such file or directory %s\nConsider using `SaveFile()` method with `createFolders=True` ", path)
		return false
	}

	fileData := f.GetFileData()
	if err := ioutil.WriteFile(path, fileData, 0644); err != nil {
		klog.Error("error savig file " + err.Error())
	}

	return true
}

func (f *KeeperFile) ToString() string {
	return fmt.Sprintf("[KeeperFile - name: %s, title: %s]", f.Name, f.Title)
}
