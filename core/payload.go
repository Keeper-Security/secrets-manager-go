package core

import (
	"encoding/json"
	"net/http"

	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

type Context struct {
	TransmissionKey TransmissionKey
	ClientId        []byte
	ClientKey       []byte
}

func NewContext(transmissionKey TransmissionKey, clientId []byte, clientKey []byte) *Context {
	return &Context{
		TransmissionKey: transmissionKey,
		ClientId:        clientId,
		ClientKey:       clientKey,
	}
}

type TransmissionKey struct {
	PublicKeyId  string
	Key          []byte
	EncryptedKey []byte
}

func NewTransmissionKey(publicKeyId string, key []byte, encryptedKey []byte) *TransmissionKey {
	return &TransmissionKey{
		PublicKeyId:  publicKeyId,
		Key:          key,
		EncryptedKey: encryptedKey,
	}
}

type GetPayload struct {
	ClientVersion    string   `json:"clientVersion"`
	ClientId         string   `json:"clientId"`
	PublicKey        string   `json:"publicKey,omitempty"`
	RequestedRecords []string `json:"requestedRecords"`
}

func (p *GetPayload) GetPayloadToJson() (string, error) {
	if pb, err := json.Marshal(p); err == nil {
		return string(pb), nil
	} else {
		klog.Error("Error serializing GetPayload to JSON: " + err.Error())
		return "", err
	}
}

func (p *GetPayload) GetPayloadFromJson(jsonData string) {
	bytes := []byte(jsonData)
	res := GetPayload{}

	if err := json.Unmarshal(bytes, &res); err == nil {
		*p = res
	} else {
		klog.Error("Error deserializing GetPayload from JSON: " + err.Error())
	}
}

type UpdatePayload struct {
	ClientVersion string `json:"clientVersion"`
	ClientId      string `json:"clientId"`
	RecordUid     string `json:"recordUid"`
	Revision      int64  `json:"revision"`
	Data          string `json:"data"`
}

func (p *UpdatePayload) UpdatePayloadToJson() (string, error) {
	if pb, err := json.Marshal(p); err == nil {
		return string(pb), nil
	} else {
		klog.Error("Error serializing UpdatePayload to JSON: " + err.Error())
		return "", err
	}
}

func (p *UpdatePayload) UpdatePayloadFromJson(jsonData string) {
	bytes := []byte(jsonData)
	res := UpdatePayload{}

	if err := json.Unmarshal(bytes, &res); err == nil {
		*p = res
	} else {
		klog.Error("Error deserializing UpdatePayload from JSON: " + err.Error())
	}
}

type CreatePayload struct {
	ClientVersion string `json:"clientVersion"`
	ClientId      string `json:"clientId"`
	RecordUid     string `json:"recordUid"`
	RecordKey     string `json:"recordKey"`
	FolderUid     string `json:"folderUid"`
	FolderKey     string `json:"folderKey"`
	Data          string `json:"data"`
}

func (p *CreatePayload) CreatePayloadToJson() (string, error) {
	if pb, err := json.Marshal(p); err == nil {
		return string(pb), nil
	} else {
		klog.Error("Error serializing CreatePayload to JSON: " + err.Error())
		return "", err
	}
}

func (p *CreatePayload) CreatePayloadFromJson(jsonData string) {
	bytes := []byte(jsonData)
	res := CreatePayload{}

	if err := json.Unmarshal(bytes, &res); err == nil {
		*p = res
	} else {
		klog.Error("Error deserializing CreatePayload from JSON: " + err.Error())
	}
}

type FileUploadPayload struct {
	ClientVersion   string `json:"clientVersion"`
	ClientId        string `json:"clientId"`
	FileRecordUid   string `json:"fileRecordUid"`
	FileRecordKey   string `json:"fileRecordKey"`
	FileRecordData  string `json:"fileRecordData"`
	OwnerRecordUid  string `json:"ownerRecordUid"`
	OwnerRecordData string `json:"ownerRecordData"`
	LinkKey         string `json:"linkKey"`
	FileSize        int    `json:"fileSize"`
}

func (p *FileUploadPayload) FileUploadPayloadToJson() (string, error) {
	if pb, err := json.Marshal(p); err == nil {
		return string(pb), nil
	} else {
		klog.Error("Error serializing FileUploadPayload to JSON: " + err.Error())
		return "", err
	}
}

func FileUploadPayloadFromJson(jsonData string) *FileUploadPayload {
	bytes := []byte(jsonData)
	res := FileUploadPayload{}

	if err := json.Unmarshal(bytes, &res); err == nil {
		return &res
	} else {
		klog.Error("Error deserializing FileUploadPayload from JSON: " + err.Error())
		return nil
	}
}

type KeeperFileUpload struct {
	Name  string
	Title string
	Type  string
	Data  []byte
}

type AddFileResponse struct {
	Url               string `json:"url"`
	Parameters        string `json:"parameters"`
	SuccessStatusCode int    `json:"successStatusCode"`
}

func AddFileResponseFromJson(jsonData string) *AddFileResponse {
	bytes := []byte(jsonData)
	res := AddFileResponse{}

	if err := json.Unmarshal(bytes, &res); err == nil {
		return &res
	} else {
		klog.Error("Error deserializing AddFileResponse from JSON: " + err.Error())
		return nil
	}
}

type EncryptedPayload struct {
	EncryptedPayload []byte
	Signature        []byte
}

func NewEncryptedPayload(encryptedPayload []byte, signature []byte) *EncryptedPayload {
	return &EncryptedPayload{
		EncryptedPayload: encryptedPayload,
		Signature:        signature,
	}
}

type KsmHttpResponse struct {
	StatusCode   int
	Data         []byte
	HttpResponse *http.Response
}

func NewKsmHttpResponse(statusCode int, data []byte, httpResponse *http.Response) *KsmHttpResponse {
	return &KsmHttpResponse{
		StatusCode:   statusCode,
		Data:         data,
		HttpResponse: httpResponse,
	}
}
