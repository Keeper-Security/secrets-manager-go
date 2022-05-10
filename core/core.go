package core

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

const (
	secretsManagerNotationPrefix   string = "keeper"
	defaultKeeperServerPublicKeyId string = "10"
)

// var (
// 	// Field types that can be inflated. Used for notation.
// 	inflateRefTypes = map[string][]string{
// 		"addressRef": []string{"address"},
// 		"cardRef":    []string{"paymentCard", "text", "pinCode", "addressRef"},
// 	}
// )

type ClientOptions struct {
	// Token specifies a One-Time Access Token used
	// to generate the configuration to use with core.SecretsManager client
	Token string

	// InsecureSkipVerify controls whether the client verifies
	// server's certificate chain and host name
	InsecureSkipVerify bool

	// Config specifies either one of the built-in IKeyValueStorage interfaces or a custom one
	Config IKeyValueStorage

	// LogLevel overrides the default log level for the logger
	LogLevel klog.LogLevel

	// Deprecated: Use Token instead. If both are set, hostname from the token takes priority.
	Hostname string
}

type SecretsManager struct {
	Token          string
	Hostname       string
	VerifySslCerts bool
	Config         IKeyValueStorage
	context        **Context
	cache          ICache
}

func NewSecretsManager(options *ClientOptions, arg ...interface{}) *SecretsManager {
	// set default values
	sm := &SecretsManager{
		VerifySslCerts: true,
	}

	// context used in tests only
	if len(arg) > 0 {
		if ctx, ok := arg[0].(**Context); ok && ctx != nil {
			sm.context = ctx
		}
	}

	// If the config is not defined and the KSM_CONFIG env var exists,
	// get the config from the env var.
	if options != nil && options.Config != nil {
		sm.Config = options.Config
	}
	ksmConfig := strings.TrimSpace(os.Getenv("KSM_CONFIG"))
	if sm.Config == nil && ksmConfig != "" {
		sm.Config = NewMemoryKeyValueStorage(ksmConfig)
		klog.Warning("Config initialised from env var KSM_CONFIG")
	} else if options != nil && strings.TrimSpace(options.Token) != "" {
		token := strings.TrimSpace(options.Token)
		hostname := strings.TrimSpace(options.Hostname)
		if tokenParts := strings.Split(token, ":"); len(tokenParts) == 1 {
			// token in legacy format without hostname prefix
			if hostname == "" {
				klog.Panicln("The hostname must be present in the token or provided as a parameter")
			}
			sm.Token = token
			sm.Hostname = hostname
		} else {
			tokenPart0 := strings.TrimSpace(tokenParts[0])
			tokenPart1 := strings.TrimSpace(tokenParts[1])
			if len(tokenParts) != 2 || tokenPart0 == "" || tokenPart1 == "" {
				klog.Warning("Expected token format 'Host:Base64Key', ex. US:ONE_TIME_TOKEN_BASE64 - got " + token)
			}
			if tokenHost, found := keeperServers[strings.ToUpper(tokenPart0)]; found {
				// token contains abbreviation: ex. "US:ONE_TIME_TOKEN"
				if hostname != "" && hostname != tokenHost {
					klog.Warning(fmt.Sprintf("Replacing hostname '%s' with token based hostname '%s'", hostname, tokenHost))
				}
				sm.Hostname = tokenHost
			} else {
				// token contains url prefix: ex. "ksm.company.com:ONE_TIME_TOKEN"
				if hostname != "" && hostname != tokenPart0 {
					klog.Warning(fmt.Sprintf("Replacing hostname '%s' with token based hostname '%s'", hostname, tokenHost))
				}
				sm.Hostname = tokenPart0
			}
			sm.Token = tokenPart1
		}
	}

	// Init the log, set log level
	if options != nil && options.LogLevel > 0 {
		klog.SetLogLevel(options.LogLevel)
	}

	if options != nil && options.InsecureSkipVerify {
		sm.VerifySslCerts = false
	}
	// Accept the env var KSM_SKIP_VERIFY
	if ksv := strings.TrimSpace(os.Getenv("KSM_SKIP_VERIFY")); ksv != "" {
		if ksvBool, err := StrToBool(ksv); err == nil {
			// We need to flip the value of KSM_SKIP_VERIFY, if true, we want VerifySslCerts to be false.
			sm.VerifySslCerts = !ksvBool
		} else {
			klog.Error("error parsing boolean value from KSM_SKIP_VERIFY=" + ksv)
		}
	}

	if sm.Config == nil {
		sm.Config = NewFileKeyValueStorage()
	}

	// If the hostname or client key are set in the args, make sure they make their way into the config.
	// They will override what is already in the config if they exist.
	if cKey := strings.TrimSpace(sm.Token); cKey != "" {
		sm.Config.Set(KEY_CLIENT_KEY, cKey)
	}
	if srv := strings.TrimSpace(sm.Hostname); srv != "" {
		sm.Config.Set(KEY_HOSTNAME, srv)
	}

	// Make sure our public key id is set and pointing an existing key.
	pkid := strings.TrimSpace(sm.Config.Get(KEY_SERVER_PUBLIC_KEY_ID))
	if pkid == "" {
		klog.Debug("Setting public key id to the default: " + defaultKeeperServerPublicKeyId)
		sm.Config.Set(KEY_SERVER_PUBLIC_KEY_ID, defaultKeeperServerPublicKeyId)
	} else if _, found := keeperServerPublicKeys[pkid]; !found {
		klog.Debug(fmt.Sprintf("Public key id %s does not exists, set to default: %s", pkid, defaultKeeperServerPublicKeyId))
		sm.Config.Set(KEY_SERVER_PUBLIC_KEY_ID, defaultKeeperServerPublicKeyId)
	}

	sm.init()
	return sm
}

func (c *SecretsManager) NotationPrefix() string {
	return secretsManagerNotationPrefix
}

func (c *SecretsManager) DefaultKeeperServerPublicKeyId() string {
	return defaultKeeperServerPublicKeyId
}

func (c *SecretsManager) SetCache(cache ICache) {
	c.cache = cache
}

func (c *SecretsManager) init() {
	clientId := strings.TrimSpace(c.Config.Get(KEY_CLIENT_ID))
	if clientId != "" {
		klog.Debug("Already bound")
		if c.Config.Get(KEY_CLIENT_KEY) != "" {
			c.Config.Delete(KEY_CLIENT_KEY)
		}
	} else {
		existingSecretKey := c.LoadSecretKey()
		if esk := strings.TrimSpace(existingSecretKey); esk == "" {
			klog.Panicln("Cannot locate One Time Token.")
		}

		existingSecretKeyBytes := UrlSafeStrToBytes(existingSecretKey)
		existingSecretKeyHash := Base64HmacFromString(existingSecretKeyBytes, clientIdHashTag)

		c.Config.Delete(KEY_CLIENT_ID)
		c.Config.Delete(KEY_PRIVATE_KEY)
		c.Config.Delete(KEY_APP_KEY)

		c.Config.Set(KEY_CLIENT_ID, existingSecretKeyHash)

		if privateKeyStr := strings.TrimSpace(c.Config.Get(KEY_PRIVATE_KEY)); privateKeyStr == "" {
			if privateKeyDer, err := GeneratePrivateKeyDer(); err == nil {
				c.Config.Set(KEY_PRIVATE_KEY, BytesToBase64(privateKeyDer))
			} else {
				klog.Panicln("Failed to generate private key. " + err.Error())
			}
		}
	}

	if !c.VerifySslCerts {
		klog.Warning("WARNING: Running without SSL cert verification. " +
			"Set 'SecretsManager.VerifySslCerts = True' or set 'KSM_SKIP_VERIFY=FALSE' " +
			"to enable verification.")
	}
}

// Returns client_id from the environment variable, config file, or in the code
func (c *SecretsManager) LoadSecretKey() string {
	// Case 1: Environment Variable
	currentSecretKey := ""
	if envSecretKey := strings.TrimSpace(os.Getenv("KSM_TOKEN")); envSecretKey != "" {
		currentSecretKey = envSecretKey
		klog.Info("Secret key found in environment variable")
	}

	// Case 2: Code
	if currentSecretKey == "" && strings.TrimSpace(c.Token) != "" {
		currentSecretKey = strings.TrimSpace(c.Token)
		klog.Info("Secret key found in code")
	}

	// Case 3: Config storage
	if currentSecretKey == "" {
		if configSecretKey := strings.TrimSpace(c.Config.Get(KEY_CLIENT_KEY)); configSecretKey != "" {
			currentSecretKey = configSecretKey
			klog.Info("Secret key found in configuration file")
		}
	}

	return strings.TrimSpace(currentSecretKey)
}

func (c *SecretsManager) GenerateTransmissionKey(keyId string) *TransmissionKey {
	serverPublicKey, ok := keeperServerPublicKeys[keyId]
	if !ok || strings.TrimSpace(serverPublicKey) == "" {
		klog.Panicf("The public key id %s does not exist.", keyId)
	}

	transmissionKey, _ := GenerateRandomBytes(Aes256KeySize)
	serverPublicRawKeyBytes := UrlSafeStrToBytes(serverPublicKey)
	encryptedKey, _ := PublicEncrypt(transmissionKey, serverPublicRawKeyBytes, nil)
	return &TransmissionKey{
		PublicKeyId:  keyId,
		Key:          transmissionKey,
		EncryptedKey: encryptedKey,
	}
}

func (c *SecretsManager) PrepareContext() *Context {
	// Get the index of the public key we need to use.
	// If not set, set it the default and save it back into the config.
	keyId := strings.TrimSpace(c.Config.Get(KEY_SERVER_PUBLIC_KEY_ID))
	if keyId == "" {
		keyId = defaultKeeperServerPublicKeyId
		c.Config.Set(KEY_SERVER_PUBLIC_KEY_ID, keyId)
	}

	// Generate the transmission key using the public key at the key id index
	transmissionKey := c.GenerateTransmissionKey(keyId)
	clientId := strings.TrimSpace(c.Config.Get(KEY_CLIENT_ID))
	secretKey := []byte{}

	// While not used in the normal operations, it's used for mocking unit tests.
	if appKey := c.Config.Get(KEY_APP_KEY); appKey != "" {
		secretKey = Base64ToBytes(appKey)
	}

	if clientId == "" {
		klog.Panicln("Client ID is missing from the configuration")
	}
	clientIdBytes := Base64ToBytes(clientId)
	context := &Context{
		TransmissionKey: *transmissionKey,
		ClientId:        clientIdBytes,
		ClientKey:       secretKey,
	}
	if c.context != nil {
		*c.context = context
	}

	return context
}

func (c *SecretsManager) encryptAndSignPayload(transmissionKey *TransmissionKey, payload interface{}) (res *EncryptedPayload, err error) {
	payloadJsonStr := ""
	switch v := payload.(type) {
	case nil:
		return nil, errors.New("error converting payload - payload == nil")
	case *GetPayload:
		if payloadJsonStr, err = v.GetPayloadToJson(); err != nil {
			return nil, errors.New("error converting get payload to JSON: " + err.Error())
		}
	case *UpdatePayload:
		if payloadJsonStr, err = v.UpdatePayloadToJson(); err != nil {
			return nil, errors.New("error converting update payload to JSON: " + err.Error())
		}
	case *CreatePayload:
		if payloadJsonStr, err = v.CreatePayloadToJson(); err != nil {
			return nil, errors.New("error converting create payload to JSON: " + err.Error())
		}
	case *FileUploadPayload:
		if payloadJsonStr, err = v.FileUploadPayloadToJson(); err != nil {
			return nil, errors.New("error converting file upload payload to JSON: " + err.Error())
		}
	default:
		return nil, fmt.Errorf("error converting payload - unknown payload type for '%v'", v)
	}

	payloadBytes := StringToBytes(payloadJsonStr)

	encryptedPayload, err := EncryptAesGcm(payloadBytes, transmissionKey.Key)
	if err != nil {
		return nil, errors.New("error encrypting the payload: " + err.Error())
	}

	encryptedKey := transmissionKey.EncryptedKey
	signatureBase := make([]byte, 0, len(encryptedKey)+len(encryptedPayload))
	signatureBase = append(signatureBase, encryptedKey...)
	signatureBase = append(signatureBase, encryptedPayload...)

	privateKey := c.Config.Get(KEY_PRIVATE_KEY)
	pk, err := DerBase64PrivateKeyToPrivateKey(privateKey)
	if err != nil {
		return nil, errors.New("error loading private key: " + err.Error())
	}

	signature, err := Sign(signatureBase, pk)
	if err != nil {
		return nil, errors.New("error generating signature: " + err.Error())
	}

	return &EncryptedPayload{
		EncryptedPayload: encryptedPayload,
		Signature:        signature,
	}, nil
}

func (c *SecretsManager) prepareGetPayload(recordsFilter []string) (res *GetPayload, err error) {
	payload := GetPayload{
		ClientVersion: keeperSecretsManagerClientId,
		ClientId:      c.Config.Get(KEY_CLIENT_ID),
	}

	if appKeyStr := c.Config.Get(KEY_APP_KEY); strings.TrimSpace(appKeyStr) == "" {
		if publicKeyBytes, err := extractPublicKeyBytes(c.Config.Get(KEY_PRIVATE_KEY)); err == nil {
			publicKeyBase64 := BytesToBase64(publicKeyBytes)
			// passed once when binding
			payload.PublicKey = publicKeyBase64
		} else {
			return nil, errors.New("error extracting public key for get payload")
		}
	}

	if len(recordsFilter) > 0 {
		payload.RequestedRecords = recordsFilter
	}

	return &payload, nil
}

func (c *SecretsManager) prepareUpdatePayload(record *Record) (res *UpdatePayload, err error) {
	payload := UpdatePayload{
		ClientVersion: keeperSecretsManagerClientId,
		ClientId:      c.Config.Get(KEY_CLIENT_ID),
	}

	// for update, UID of the record
	payload.RecordUid = record.Uid
	payload.Revision = record.Revision

	// #TODO: This is where we need to get JSON of the updated Record
	// rawJson := DictToJson(record.RecordDict)
	rawJsonBytes := StringToBytes(record.RawJson)
	if encryptedRawJsonBytes, err := EncryptAesGcm(rawJsonBytes, record.RecordKeyBytes); err == nil {
		payload.Data = BytesToUrlSafeStr(encryptedRawJsonBytes)
	} else {
		return nil, err
	}

	return &payload, nil
}

func (c *SecretsManager) prepareCreatePayload(record *Record) (res *CreatePayload, err error) {
	payload := CreatePayload{
		ClientVersion: keeperSecretsManagerClientId,
		ClientId:      c.Config.Get(KEY_CLIENT_ID),
	}

	ownerPublicKey := strings.TrimSpace(c.Config.Get(KEY_OWNER_PUBLIC_KEY))
	if ownerPublicKey == "" {
		return nil, fmt.Errorf("unable to create record - owner key is missing. Looks like application was created using outdated client (Web Vault or Commander)")
	}
	ownerPublicKeyBytes := Base64ToBytes(ownerPublicKey)

	if strings.TrimSpace(record.folderUid) == "" {
		return nil, fmt.Errorf("unable to create record - missing folder UID")
	}
	if len(record.folderKeyBytes) == 0 {
		return nil, fmt.Errorf("unable to create record - folder key for '%s' missing", record.folderUid)
	}
	if strings.TrimSpace(payload.ClientId) == "" {
		return nil, fmt.Errorf("unable to create record - client Id is missing from the configuration")
	}
	if record == nil {
		return nil, fmt.Errorf("unable to create record - missing record data")
	}

	// convert any record UID in Base64 encoding to UrlSafeBase64
	recordUid := BytesToUrlSafeStr(Base64ToBytes(record.Uid))

	payload.RecordUid = recordUid
	payload.FolderUid = record.folderUid

	rawJsonBytes := StringToBytes(record.RawJson)
	if encryptedRawJsonBytes, err := EncryptAesGcm(rawJsonBytes, record.RecordKeyBytes); err == nil {
		payload.Data = BytesToBase64(encryptedRawJsonBytes)
	} else {
		return nil, err
	}

	if encryptedFolderKey, err := EncryptAesGcm(record.RecordKeyBytes, record.folderKeyBytes); err == nil {
		payload.FolderKey = BytesToBase64(encryptedFolderKey)
	} else {
		return nil, err
	}

	if encryptedRecordKey, err := PublicEncrypt(record.RecordKeyBytes, ownerPublicKeyBytes, nil); err == nil {
		payload.RecordKey = BytesToBase64(encryptedRecordKey)
	} else {
		return nil, err
	}

	return &payload, nil
}

func (c *SecretsManager) prepareFileUploadPayload(record *Record, file *KeeperFileUpload) (res *FileUploadPayload, encFileData []byte, err error) {
	payload := FileUploadPayload{
		ClientVersion: keeperSecretsManagerClientId,
		ClientId:      c.Config.Get(KEY_CLIENT_ID),
	}
	if strings.TrimSpace(payload.ClientId) == "" {
		return nil, nil, fmt.Errorf("unable to create record - client Id is missing from the configuration")
	}
	if record == nil {
		return nil, nil, fmt.Errorf("unable to create record - missing record data")
	}

	ownerPublicKey := strings.TrimSpace(c.Config.Get(KEY_OWNER_PUBLIC_KEY))
	if ownerPublicKey == "" {
		return nil, nil, fmt.Errorf("unable to create record - owner key is missing. Looks like application was created using outdated client (Web Vault or Commander)")
	}
	ownerPublicKeyBytes := Base64ToBytes(ownerPublicKey)

	// lastModified := time.Now().UnixMilli() // go1.17+
	lastModified := time.Now().UnixNano() / int64(time.Millisecond)
	fileData := KeeperFileData{
		Title:        file.Title,
		Name:         file.Name,
		Type:         file.Type,
		Size:         int64(len(file.Data)),
		LastModified: lastModified,
	}

	fileRecordBytes := ""
	if fd, err := json.Marshal(fileData); err == nil {
		fileRecordBytes = string(fd)
	} else {
		return nil, nil, err
	}

	fileRecordKeyBytes, _ := GetRandomBytes(32)
	fileRecordUidBytes, _ := GetRandomBytes(16)
	payload.FileRecordUid = BytesToUrlSafeStr(fileRecordUidBytes)

	if encryptedFileRecord, err := EncryptAesGcm([]byte(fileRecordBytes), fileRecordKeyBytes); err == nil {
		payload.FileRecordData = BytesToUrlSafeStr(encryptedFileRecord)
	} else {
		return nil, nil, err
	}
	if encryptedFileRecordKey, err := PublicEncrypt(fileRecordKeyBytes, ownerPublicKeyBytes, nil); err == nil {
		payload.FileRecordKey = BytesToBase64(encryptedFileRecordKey)
	} else {
		return nil, nil, err
	}
	if encryptedLinkKey, err := EncryptAesGcm(fileRecordKeyBytes, record.RecordKeyBytes); err == nil {
		payload.LinkKey = BytesToBase64(encryptedLinkKey)
	} else {
		return nil, nil, err
	}

	encryptedFileData, err := EncryptAesGcm(file.Data, fileRecordKeyBytes)
	if err == nil {
		payload.FileSize = len(encryptedFileData)
	} else {
		return nil, nil, err
	}

	payload.OwnerRecordUid = record.Uid

	fileRefs, err := record.GetStandardFieldValue("fileRef", false)
	if err != nil {
		return nil, nil, err
	}
	if len(fileRefs) > 0 {
		fileRefs = append(fileRefs, payload.FileRecordUid)
		record.SetStandardFieldValue("fileRef", fileRefs)
	} else {
		record.SetStandardFieldValue("fileRef", payload.FileRecordUid)
	}

	ownerRecordJson := DictToJson(record.RecordDict)
	ownerRecordBytes := StringToBytes(ownerRecordJson)
	if encryptedOwnerRecord, err := EncryptAesGcm(ownerRecordBytes, record.RecordKeyBytes); err == nil {
		payload.OwnerRecordData = BytesToUrlSafeStr(encryptedOwnerRecord)
	} else {
		return nil, nil, err
	}

	return &payload, encryptedFileData, nil
}

func (c *SecretsManager) PostQuery(path string, payload interface{}) (body []byte, err error) {
	keeperServer := GetServerHostname(c.Hostname, c.Config)
	url := fmt.Sprintf("https://%s/api/rest/sm/v1/%s", keeperServer, path)
	var transmissionKey *TransmissionKey
	var ksmRs *KsmHttpResponse
	if c.context != nil {
		*c.context = c.PrepareContext()
	}

	for {
		transmissionKeyId := strings.TrimSpace(c.Config.Get(KEY_SERVER_PUBLIC_KEY_ID))
		if transmissionKeyId == "" {
			transmissionKeyId = defaultKeeperServerPublicKeyId
			c.Config.Set(KEY_SERVER_PUBLIC_KEY_ID, transmissionKeyId)
		}

		transmissionKey = c.GenerateTransmissionKey(transmissionKeyId)
		if c.context != nil {
			(*c.context).TransmissionKey = *transmissionKey
		}
		encryptedPayloadAndSignature, err := c.encryptAndSignPayload(transmissionKey, payload)
		if err != nil {
			return nil, errors.New("error encrypting payload: " + err.Error())
		}

		ksmRs, err = c.PostFunction(url, transmissionKey, encryptedPayloadAndSignature, c.VerifySslCerts)
		if err != nil {
			return nil, errors.New("error during POST request: " + err.Error())
		}

		if c.cache != nil && path == "get_secret" {
			success := true
			if ksmRs != nil && ksmRs.StatusCode == 200 {
				data := make([]byte, 0, len(transmissionKey.Key)+len(ksmRs.Data))
				data = append(data, transmissionKey.Key...)
				data = append(data, ksmRs.Data...)
				c.cache.SaveCachedValue(data)
			} else {
				if cachedData, cerr := c.cache.GetCachedValue(); cerr == nil && len(cachedData) >= Aes256KeySize {
					transmissionKey.Key = cachedData[:Aes256KeySize]
					data := cachedData[Aes256KeySize:]
					ksmRs = NewKsmHttpResponse(200, data, nil)
				} else {
					success = false
				}
			}
			if success {
				break
			}
		}

		// If we are ok, then break out of the while loop
		if ksmRs.StatusCode == 200 {
			break
		}

		// Handle the error. Handler will return a retry status if it is a recoverable error.
		if retry, err := c.HandleHttpError(ksmRs.HttpResponse, ksmRs.Data, err); !retry {
			errMsg := "N/A"
			if err != nil {
				errMsg = err.Error()
			}
			klog.Panicln("POST Error: " + errMsg)
		}
	}

	if ksmRs != nil && len(ksmRs.Data) > 0 {
		decryptedResponseBytes, err := Decrypt(ksmRs.Data, transmissionKey.Key)
		return decryptedResponseBytes, err
	}

	// break out of the loop only on success - empty body/data is a valid response ex. for update
	return []byte{}, err
}

func (c *SecretsManager) PostFunction(
	url string,
	transmissionKey *TransmissionKey,
	encryptedPayloadAndSignature *EncryptedPayload,
	verifySslCerts bool) (*KsmHttpResponse, error) {

	rq, err := http.NewRequest("POST", url, bytes.NewBuffer(encryptedPayloadAndSignature.EncryptedPayload))
	if err != nil {
		return NewKsmHttpResponse(0, nil, nil), err
	}

	rq.Header.Set("Content-Type", "application/octet-stream")
	rq.Header.Set("Content-Length", fmt.Sprint(len(encryptedPayloadAndSignature.EncryptedPayload)))
	rq.Header.Set("PublicKeyId", transmissionKey.PublicKeyId)
	rq.Header.Set("TransmissionKey", BytesToBase64(transmissionKey.EncryptedKey))
	rq.Header.Set("Authorization", fmt.Sprintf("Signature %s", BytesToBase64(encryptedPayloadAndSignature.Signature)))
	// klog.Debug(rq.Header)

	tr := http.DefaultClient.Transport
	if insecureSkipVerify := !verifySslCerts; insecureSkipVerify {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		}
	}
	client := &http.Client{Transport: tr}

	rs, err := client.Do(rq)
	if err != nil {
		return NewKsmHttpResponse(0, nil, rs), err
	}
	defer rs.Body.Close()

	rsBody, err := ioutil.ReadAll(rs.Body)
	return NewKsmHttpResponse(rs.StatusCode, rsBody, rs), err
}

func (c *SecretsManager) HandleHttpError(rs *http.Response, body []byte, httpError error) (retry bool, err error) {
	retry = false
	err = httpError
	logMessage := fmt.Sprintf("Error: %s  (http error code: %d, raw: %s)", rs.Status, rs.StatusCode, string(body))

	// switch to warning for recoverable errors - ex. key rotation
	keyRotation := false
	if matched, err := regexp.MatchString(`"key_id"\s*:\s*\d+\s*(?:\,|\})`, string(body)); err == nil && matched {
		if matched, err = regexp.MatchString(`"error"\s*:\s*"key"|"message"\s*:\s*"invalid key id"`, string(body)); err == nil && matched {
			keyRotation = true
		}
	}

	if keyRotation {
		klog.Warning(logMessage)
	} else {
		klog.Error(logMessage)
	}

	responseDict := JsonToDict(string(body))
	if len(responseDict) == 0 {
		// This is an unknown error, not one of ours, just throw a HTTPError
		return false, errors.New("HTTPError: " + string(body))
	}

	// Try to get the error from result_code, then from error.
	msg := ""
	rc, found := responseDict["result_code"]
	if !found {
		rc, found = responseDict["error"]
	}
	if found && rc.(string) == "invalid_client_version" {
		klog.Error(fmt.Sprintf("Client version %s was not registered in the backend", keeperSecretsManagerClientId))
		if additionalInfo, found := responseDict["additional_info"]; found {
			msg = additionalInfo.(string)
		}
	} else if found && rc.(string) == "key" {
		// The server wants us to use a different public key.
		keyId := ""
		if kid, ok := responseDict["key_id"]; ok {
			keyId = fmt.Sprintf("%v", kid)
		}
		klog.Info(fmt.Sprintf("Server has requested we use public key %v", keyId))
		if len(keyId) == 0 {
			msg = "The public key is blank from the server"
		} else if _, found := keeperServerPublicKeys[keyId]; found {
			c.Config.Set(KEY_SERVER_PUBLIC_KEY_ID, keyId)
			// The only normal exit from this method
			return true, nil
		} else {
			msg = fmt.Sprintf("The public key at %v does not exist in the SDK", keyId)
		}
	} else {
		responseMsg, ok := responseDict["message"]
		if !ok {
			responseMsg = "N/A"
		}
		msg = fmt.Sprintf("Error: %v, message=%v", rc, responseMsg)
	}

	if msg != "" {
		err = errors.New(msg)
	} else if len(body) > 0 {
		err = errors.New(string(body))
	}

	return
}

func (c *SecretsManager) fetchAndDecryptSecrets(recordFilter []string) (smr *SecretsManagerResponse, err error) {
	records := []*Record{}
	folders := []*Folder{}
	justBound := false

	payload, err := c.prepareGetPayload(recordFilter)
	if err != nil {
		return nil, err
	}

	decryptedResponseBytes, err := c.PostQuery("get_secret", payload)
	if err != nil {
		return nil, err
	}

	decryptedResponseStr := BytesToString(decryptedResponseBytes)
	decryptedResponseDict := JsonToDict(decryptedResponseStr)

	var secretKey []byte
	if encryptedAppKey, found := decryptedResponseDict["encryptedAppKey"]; found && encryptedAppKey != nil && fmt.Sprintf("%v", encryptedAppKey) != "" {
		justBound = true
		clientKey := UrlSafeStrToBytes(c.Config.Get(KEY_CLIENT_KEY))
		if len(clientKey) == 0 {
			return nil, errors.New("client key is missing from the storage")
		}
		encryptedMasterKey := UrlSafeStrToBytes(encryptedAppKey.(string))
		if secretKey, err = Decrypt(encryptedMasterKey, clientKey); err == nil {
			c.Config.Set(KEY_APP_KEY, BytesToBase64(secretKey))
			c.Config.Delete(KEY_CLIENT_KEY)
		} else {
			klog.Error("failed to decrypt APP_KEY")
		}
		if ownerPubKey, found := decryptedResponseDict[string(KEY_OWNER_PUBLIC_KEY)]; found && ownerPubKey != nil {
			if appOwnerPublicKey := strings.TrimSpace(fmt.Sprintf("%v", ownerPubKey)); appOwnerPublicKey != "" {
				c.Config.Set(KEY_OWNER_PUBLIC_KEY, appOwnerPublicKey)
			}
		}
	} else {
		secretKey = Base64ToBytes(c.Config.Get(KEY_APP_KEY))
		if len(secretKey) == 0 {
			return nil, errors.New("app key is missing from the storage")
		}
	}

	recordsResp := decryptedResponseDict["records"]
	foldersResp := decryptedResponseDict["folders"]

	recordCount := 0
	emptyInterfaceSlice := []interface{}{}
	if recordsResp != nil {
		if reflect.TypeOf(recordsResp) == reflect.TypeOf(emptyInterfaceSlice) {
			for _, r := range recordsResp.([]interface{}) {
				recordCount++
				record := NewRecordFromJson(r.(map[string]interface{}), secretKey, "")
				records = append(records, record)
			}
		} else {
			klog.Error("record JSON is in incorrect format")
		}
	}

	folderCount := 0
	if foldersResp != nil {
		if reflect.TypeOf(foldersResp) == reflect.TypeOf(emptyInterfaceSlice) {
			for _, f := range foldersResp.([]interface{}) {
				folderCount++
				folder := NewFolderFromJson(f.(map[string]interface{}), secretKey)
				if f != nil {
					records = append(records, folder.Records()...)
					folders = append(folders, folder)
				} else {
					klog.Error("error parsing folder JSON: ", f)
				}
			}
		} else {
			klog.Error("folder JSON is in incorrect format")
		}
	}

	klog.Debug(fmt.Sprintf("Individual record count: %d", recordCount))
	klog.Debug(fmt.Sprintf("Folder count: %d", folderCount))
	klog.Debug(fmt.Sprintf("Total record count: %d", len(records)))

	smResponse := SecretsManagerResponse{
		Records:   records,
		Folders:   folders,
		JustBound: justBound,
	}

	if appDataB64, found := decryptedResponseDict["appData"]; found && appDataB64 != nil && fmt.Sprintf("%v", appDataB64) != "" {
		appDataBytes := UrlSafeStrToBytes(appDataB64.(string))
		appKey := Base64ToBytes(c.Config.Get(KEY_APP_KEY))
		if appDataJson, err := Decrypt(appDataBytes, appKey); err == nil {
			appData := AppData{}
			if err := json.Unmarshal([]byte(appDataJson), &appData); err == nil {
				smResponse.AppData = appData
			} else {
				klog.Error("Error deserializing appData from JSON: " + err.Error())
			}
		} else {
			klog.Warning("Failed to decrypt appData - " + err.Error())
		}
	}
	if expiresOn, found := decryptedResponseDict["expiresOn"]; found && expiresOn != nil && fmt.Sprintf("%v", expiresOn) != "" {
		if i, err := strconv.ParseInt(fmt.Sprintf("%v", expiresOn), 10, 0); err == nil {
			smResponse.ExpiresOn = i
		} else {
			klog.Error("Error parsing ExpiresOn: " + err.Error())
		}
	}
	if warnings, found := decryptedResponseDict["warnings"]; found && warnings != nil && fmt.Sprintf("%v", warnings) != "" {
		smResponse.Warnings = fmt.Sprintf("%v", warnings)
	}

	return &smResponse, nil
}

func (c *SecretsManager) getSecretsFullResponse(uids []string) (records []*Record, folders []*Folder, err error) {
	// Retrieve all records associated with the given application
	recordsResp, err := c.fetchAndDecryptSecrets(uids)
	if err != nil {
		return nil, nil, err
	}
	if recordsResp.JustBound {
		recordsResp, err = c.fetchAndDecryptSecrets(uids)
		if err != nil {
			return nil, nil, err
		}
	}

	// Log warnings we got from the server
	// Will only be displayed if logging is enabled:
	if recordsResp.Warnings != "" {
		klog.Warning(recordsResp.Warnings)
	}

	return recordsResp.Records, recordsResp.Folders, nil
}

func (c *SecretsManager) GetSecrets(uids []string) (records []*Record, err error) {
	records, _, err = c.getSecretsFullResponse(uids)
	return records, err
}

func (c *SecretsManager) GetSecretsByTitle(recordTitle string) (records []*Record, err error) {
	if records, err := c.GetSecrets([]string{}); err != nil {
		return nil, err
	} else {
		return FindSecretsByTitle(recordTitle, records), nil
	}
}

func (c *SecretsManager) GetSecretByTitle(recordTitle string) (record *Record, err error) {
	if records, err := c.GetSecrets([]string{}); err != nil {
		return nil, err
	} else {
		return FindSecretByTitle(recordTitle, records), nil
	}
}

func FindSecretByTitle(recordTitle string, records []*Record) *Record {
	for _, r := range records {
		if r.Title() == recordTitle {
			return r
		}
	}
	return nil
}

func FindSecretsByTitle(recordTitle string, records []*Record) []*Record {
	recordsByTitle := []*Record{}
	for _, r := range records {
		if r.Title() == recordTitle {
			recordsByTitle = append(recordsByTitle, r)
		}
	}
	return recordsByTitle
}

func (c *SecretsManager) Save(record *Record) (err error) {
	// Save updated secret values
	klog.Info("Updating record uid: " + record.Uid)

	payload, err := c.prepareUpdatePayload(record)
	if err != nil {
		return err
	}

	_, err = c.PostQuery("update_secret", payload)
	return err
}

func (c *SecretsManager) UploadFile(record *Record, file *KeeperFileUpload) (uid string, err error) {
	klog.Info("Uploading file for record uid: " + record.Uid)

	payload, encryptedFileData, err := c.prepareFileUploadPayload(record, file)
	if err != nil {
		return "", err
	}

	responseData, err := c.PostQuery("add_file", payload)
	if err != nil {
		return "", err
	}

	response := AddFileResponseFromJson(string(responseData))

	if err := c.fileUpload(response.Url, response.Parameters, response.SuccessStatusCode, encryptedFileData); err != nil {
		return "", err
	}

	return payload.FileRecordUid, nil
}

func (c *SecretsManager) fileUpload(url, parameters string, successStatusCode int, fileData []byte) error {
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)

	var jsParams map[string]string
	err := json.Unmarshal([]byte(parameters), &jsParams)
	if err != nil {
		return err
	}
	for key, val := range jsParams {
		if err := w.WriteField(key, val); err != nil {
			return err
		}
	}

	fw, err := w.CreateFormFile("file", "")
	if err != nil {
		return err
	}
	if _, err = fw.Write(fileData); err != nil {
		return err
	}

	// create terminating boundary
	if err := w.Close(); err != nil {
		return err
	}

	rq, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}

	rq.Header.Set("Content-Type", w.FormDataContentType())

	tr := http.DefaultClient.Transport
	if insecureSkipVerify := !c.VerifySslCerts; insecureSkipVerify {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		}
	}
	client := &http.Client{Transport: tr}

	rs, err := client.Do(rq)
	if err != nil {
		return err
	}
	defer rs.Body.Close()

	if rs.StatusCode != successStatusCode {
		return fmt.Errorf("upload failed, status code %v", rs.StatusCode)
	}

	// PostResponse XML is ignored - verify status code for success
	// rs.Header["Content-Type"][0] == "application/xml"
	rsBody, err := ioutil.ReadAll(rs.Body)
	if err != nil {
		return err
	}
	if len(rsBody) == 0 {
		return fmt.Errorf("upload failed - XML response was expected but not received")
	}

	return nil
}

func (c *SecretsManager) CreateSecret(record *Record) (recordUid string, err error) {
	payload, err := c.prepareCreatePayload(record)
	if err != nil {
		return "", err
	}

	_, err = c.PostQuery("create_secret", payload)
	return payload.RecordUid, err
}

// CreateSecretWithRecordData creates new record using recordUID, folderUID and record data provided
// Note: if param recUid is empty - new auto generated record UID will be used
func (c *SecretsManager) CreateSecretWithRecordData(recUid, folderUid string, recordData *RecordCreate) (recordUid string, err error) {
	// Backend only needs a JSON string of the record, so we have different ways of handing data:
	//   - providing data as JSON string
	//   - providing data as map[string]interface{}
	//   - providing data as CreateRecord struct
	// Here we will use CreateRecord objects

	if recordData == nil || recordData.RecordType == "" || recordData.Title == "" {
		return "", errors.New("new record data has to be a valid 'RecordCreate' object")
	}

	// Since we don't know folder's key where this record will be placed in,
	// currently we have to retrieve all data that is share to this device/client
	// and look for the folder's key in the returned folder data

	_, folders, err := c.getSecretsFullResponse([]string{})
	if err != nil {
		return "", err
	}

	foundFolder := GetFolderByKey(folderUid, folders)
	if foundFolder == nil {
		return "", fmt.Errorf("folder uid='%s' was not retrieved. If you are creating a record in a "+
			"shared folder that you know exists, make sure that at least one record is present in "+
			"the folder prior to adding a new record", folderUid)
	}

	record := NewRecordFromRecordDataWithUid(recUid, recordData, foundFolder)
	if record == nil {
		return "", fmt.Errorf("failed to create new record from record data: %v", recordData)
	}
	payload, err := c.prepareCreatePayload(record)
	if err != nil {
		return "", err
	}

	_, err = c.PostQuery("create_secret", payload)
	return payload.RecordUid, err
}

type notationOptions struct {
	url           string
	uid           string
	fieldDataType string
	key           string
	returnSingle  bool
	index         int
	dictKey       string
}

func (c *SecretsManager) parseNotation(notationUrl string) (nopts *notationOptions, err error) {
	// ex. URL: <uid>/<field|custom_field|file>/<label|type>[INDEX][FIELD]
	opts := notationOptions{url: notationUrl}
	// If the URL starts with keeper:// we want to remove it.
	if strings.HasPrefix(strings.ToLower(notationUrl), c.NotationPrefix()) {
		errMisingPath := errors.New("keeper url missing information about the uid, field type, and field key")
		if urlParts := strings.Split(notationUrl, "//"); len(urlParts) > 1 {
			if notationUrl = urlParts[1]; notationUrl == "" {
				return nil, errMisingPath
			}
		} else {
			return nil, errMisingPath
		}
	}

	if urlParts := strings.Split(notationUrl, "/"); len(urlParts) == 3 {
		opts.uid = urlParts[0]
		opts.fieldDataType = urlParts[1]
		opts.key = urlParts[2]
	} else {
		return nil, fmt.Errorf("could not parse the notation '%s'. Is it valid? ", notationUrl)
	}

	if opts.uid == "" {
		return nil, errors.New("record UID is missing in the keeper url")
	}
	if opts.fieldDataType == "" {
		return nil, errors.New("field type is missing in the keeper url")
	}
	if opts.key == "" {
		return nil, errors.New("field key is missing in the keeper url")
	}

	// By default, we want to return a single value, which is the first item in the array
	opts.returnSingle = true
	opts.index = 0
	opts.dictKey = ""

	// Check it see if the key has a predicate, possibly with an index.
	rePredicate := regexp.MustCompile(`\[([^\]]*)\]`)
	rePredicateValue := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if predicates := rePredicate.FindAllStringSubmatch(opts.key, 3); len(predicates) > 0 {
		if len(predicates) > 2 {
			return nil, errors.New("the predicate of the notation appears to be invalid. Too many [], max 2 allowed. ")
		}
		if firstPredicate := predicates[0]; len(firstPredicate) > 1 {
			value := firstPredicate[1]
			// If the first predicate is an index into an array - fileRef[2]
			if i, err := strconv.ParseInt(value, 10, 64); err == nil {
				opts.index = int(i)
			} else if matched := rePredicateValue.MatchString(value); matched {
				// the first predicate is a key to a dictionary - name[first]
				opts.dictKey = value
			} else {
				// else it was an array indicator (.../name[] or .../name) - return all the values
				opts.returnSingle = false
			}
		}
		if len(predicates) > 1 {
			if !opts.returnSingle {
				return nil, errors.New("if the second [] is a dictionary key, the first [] needs to have any index. ")
			}
			if secondPredicate := predicates[1]; len(secondPredicate) > 1 {
				if value := secondPredicate[1]; len(value) > 0 {
					// If the second predicate is an index into an array - fileRef[2]
					if _, err := strconv.ParseInt(value, 10, 64); err == nil {
						return nil, errors.New("the second [] can only by a key for the dictionary. It cannot be an index. ")
					} else if matched := rePredicateValue.MatchString(value); matched {
						// the second predicate is a key to a dictionary - name[first]
						opts.dictKey = value
					} else {
						// else it was an array indicator (.../name[] or .../name) - return all the values
						return nil, errors.New("the second [] must have key for the dictionary. Cannot be blank. ")
					}
				}
			}
		}

		// Remove the predicate from the key, if it exists
		if pos := strings.Index(opts.key, "["); pos >= 0 {
			opts.key = opts.key[:pos]
		}
	}

	return &opts, nil
}

func (c *SecretsManager) extractNotation(records []*Record, nopts *notationOptions) (fieldValue []interface{}, err error) {
	fieldValue = []interface{}{}

	matchingRecords := []*Record{}
	for _, r := range records {
		if r.Uid == nopts.uid {
			matchingRecords = append(matchingRecords, r)
		}
	}

	if len(matchingRecords) == 0 {
		return fieldValue, errors.New("Could not find a record with the UID " + nopts.uid)
	}
	if len(matchingRecords) > 1 {
		klog.Warning("Found more that one record with the same UID. Notation will inspect only the first record!")
	}

	record := matchingRecords[0]

	var iValue []interface{}
	if nopts.fieldDataType == "field" {
		field := record.getStandardField(nopts.key)
		if len(field) == 0 {
			return fieldValue, fmt.Errorf("cannot find standard field %s", nopts.key)
		}
		iValue, _ = field["value"].([]interface{})
		// fieldType, _ = field["type"].(string)
	} else if nopts.fieldDataType == "custom_field" {
		// iValue = record.GetCustomFieldsByLabel(nopts.key) // by default custom[] searches are by label
		field := record.getCustomField(nopts.key)
		if len(field) == 0 {
			return fieldValue, fmt.Errorf("cannot find custom field %s", nopts.key)
		}
		iValue, _ = field["value"].([]interface{})
		// fieldType, _ = field["type"].(string)
	} else if nopts.fieldDataType == "file" {
		file := record.FindFileByTitle(nopts.key)
		if file == nil {
			return fieldValue, fmt.Errorf("cannot find the file %s in record %s. ", nopts.key, nopts.uid)
		}
		fieldValue = append(fieldValue, file.GetFileData())
		return fieldValue, nil
	} else {
		return fieldValue, fmt.Errorf("field type of %s is not valid. ", nopts.fieldDataType)
	}

	// Inflate the value if its part of list of types to inflate.
	// This will request additional records	from secrets manager.
	// if ftypes, found := inflateRefTypes[fieldType]; found {
	// 	iValue := inflateFieldValue(iValue, ftypes)
	// }

	if nopts.returnSingle {
		if len(iValue) == 0 {
			return fieldValue, nil
		}
		if len(iValue) > nopts.index {
			iVal := iValue[nopts.index]
			retMap, mapOk := iVal.(map[string]interface{})
			if mapOk && strings.TrimSpace(nopts.dictKey) != "" {
				if val, ok := retMap[nopts.dictKey]; ok {
					fieldValue = append(fieldValue, val)
				} else {
					return fieldValue, fmt.Errorf("cannot find the dictionary key %s in the value ", nopts.dictKey)
				}
			} else {
				fieldValue = append(fieldValue, iVal)
			}
			if len(fieldValue) > 0 {
				if strValue, ok := fieldValue[0].(string); ok {
					fieldValue = []interface{}{strValue}
				} else if mapValue, ok := fieldValue[0].(map[string]interface{}); ok {
					if v, ok := mapValue["value"].([]interface{}); ok {
						if len(v) > 0 {
							fieldValue = []interface{}{fmt.Sprintf("%v", v[0])}
						} else {
							fieldValue = []interface{}{""}
						}
					}
				}
			}
		} else {
			return fieldValue, fmt.Errorf("the value at index %d does not exist for %s. ", nopts.index, nopts.url)
		}
	} else {
		fieldValue = iValue
	}

	return fieldValue, nil
}

func (c *SecretsManager) FindNotation(records []*Record, url string) (fieldValue []interface{}, err error) {
	nopts, err := c.parseNotation(url)
	if err != nil {
		return []interface{}{}, err
	}

	return c.extractNotation(records, nopts)
}

func (c *SecretsManager) GetNotation(url string) (fieldValue []interface{}, err error) {
	/*
		Simple string notation to get a value

		* A system of figures or symbols used in a specialized field to represent numbers, quantities, tones,
			or values.

		<uid>/<field|custom_field|file>/<label|type>[INDEX][FIELD]

		Example:

			RECORD_UID/field/password                => MyPassword
			RECORD_UID/field/password[0]             => MyPassword
			RECORD_UID/field/password[]              => ["MyPassword"]
			RECORD_UID/custom_field/name[first]      => John
			RECORD_UID/custom_field/name[last]       => Smith
			RECORD_UID/custom_field/phone[0][number] => "555-5555555"
			RECORD_UID/custom_field/phone[1][number] => "777-7777777"
			RECORD_UID/custom_field/phone[]          => [{"number": "555-555...}, { "number": "777.....}]
			RECORD_UID/custom_field/phone[0]         => [{"number": "555-555...}]
	*/

	nopts, err := c.parseNotation(url)
	if err != nil {
		return []interface{}{}, err
	}

	records, err := c.GetSecrets([]string{nopts.uid})
	if err != nil {
		return []interface{}{}, err
	}

	return c.extractNotation(records, nopts)
}
