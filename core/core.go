package core

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

const (
	secretsManagerNotationPrefix   string = "keeper"
	defaultKeeperServerPublicKeyId string = "7"
)

type SecretsManager struct {
	Token          string
	HostName       string
	VerifySslCerts bool
	Config         IKeyValueStorage
	context        **Context
	cache          ICache
}

func NewSecretsManager() *SecretsManager {
	sm := &SecretsManager{
		VerifySslCerts: true,
	}
	sm.init()
	return sm
}

func NewSecretsManagerFromConfig(config IKeyValueStorage, arg ...interface{}) *SecretsManager {
	sm := &SecretsManager{
		VerifySslCerts: true,
		Config:         config,
	}
	if len(arg) > 0 {
		if ctx, ok := arg[0].(**Context); ok && ctx != nil {
			sm.context = ctx
		}
	}
	sm.init()
	return sm
}

func NewSecretsManagerFromSettings(token string, hostname string, verifySslCerts bool) *SecretsManager {
	return NewSecretsManagerFromFullSetup(token, hostname, verifySslCerts, NewFileKeyValueStorage())
}

func NewSecretsManagerFromFullSetup(token string, hostname string, verifySslCerts bool, config IKeyValueStorage) *SecretsManager {
	if config == nil {
		config = NewFileKeyValueStorage()
	}

	// If the hostname or client key are set in the args, make sure they make their way into the config.
	// They will override what is already in the config if they exist.
	if cKey := strings.TrimSpace(token); cKey != "" {
		config.Set(KEY_CLIENT_KEY, cKey)
	}
	if srv := strings.TrimSpace(hostname); srv != "" {
		config.Set(KEY_HOSTNAME, srv)
	}

	sm := &SecretsManager{
		Token:          token,
		HostName:       hostname,
		VerifySslCerts: verifySslCerts,
		Config:         config,
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
	klog.SetLogLevel(klog.InfoLevel)

	// Accept the env var KSM_SKIP_VERIFY
	if ksv := strings.TrimSpace(os.Getenv("KSM_SKIP_VERIFY")); ksv != "" {
		if ksvBool, err := StrToBool(ksv); err == nil {
			// We need to flip the value of KSM_SKIP_VERIFY, if true, we want VerifySslCerts to be false.
			c.VerifySslCerts = !ksvBool
		} else {
			klog.Error("error parsing boolean value from KSM_SKIP_VERIFY=" + ksv)
		}
	}

	if c.Config == nil {
		c.Config = NewFileKeyValueStorage()
	}
	c.loadConfig()

	// Make sure our public key id is set and pointing an existing key.
	pkid := strings.TrimSpace(c.Config.Get(KEY_SERVER_PUBLIC_KEY_ID))
	if pkid == "" {
		klog.Debug("Setting public key id to the default: " + defaultKeeperServerPublicKeyId)
		c.Config.Set(KEY_SERVER_PUBLIC_KEY_ID, defaultKeeperServerPublicKeyId)
	} else if _, found := keeperServerPublicKeys[pkid]; !found {
		klog.Debug(fmt.Sprintf("Public key id %s does not exists, set to default: %s", pkid, defaultKeeperServerPublicKeyId))
		c.Config.Set(KEY_SERVER_PUBLIC_KEY_ID, defaultKeeperServerPublicKeyId)
	}
}

func (c *SecretsManager) loadConfig() {
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

		existingSecretKeyHash := UrlSafeHmacFromString(existingSecretKey, clientIdHashTag)

		c.Config.Delete(KEY_CLIENT_ID)
		c.Config.Delete(KEY_PRIVATE_KEY)
		c.Config.Delete(KEY_APP_KEY)

		c.Config.Set(KEY_CLIENT_ID, existingSecretKeyHash)

		if privateKeyStr := strings.TrimSpace(c.Config.Get(KEY_PRIVATE_KEY)); privateKeyStr == "" {
			if privateKeyDer, err := GeneratePrivateKeyDer(); err == nil {
				c.Config.Set(KEY_PRIVATE_KEY, BytesToUrlSafeStr(privateKeyDer))
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

func (c *SecretsManager) GenerateTransmissionKey(keyId string) TransmissionKey {
	serverPublicKey, ok := keeperServerPublicKeys[keyId]
	if !ok || strings.TrimSpace(serverPublicKey) == "" {
		klog.Panicf("The public key id %s does not exist.", keyId)
	}

	transmissionKey, _ := GenerateRandomBytes(Aes256KeySize)
	serverPublicRawKeyBytes := UrlSafeStrToBytes(serverPublicKey)
	encryptedKey, _ := PublicEncrypt(transmissionKey, serverPublicRawKeyBytes, nil)
	result := TransmissionKey{
		PublicKeyId:  keyId,
		Key:          transmissionKey,
		EncryptedKey: encryptedKey,
	}

	return result
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
		TransmissionKey: transmissionKey,
		ClientId:        clientIdBytes,
		ClientKey:       secretKey,
	}
	if c.context != nil {
		*c.context = context
	}

	return context
}

func (c *SecretsManager) encryptAndSignPayload(context *Context, payloadJson string) (res EncryptedPayload, err error) {
	payloadBytes := StringToBytes(payloadJson)

	encryptedPayload, err := EncryptAesGcm(payloadBytes, context.TransmissionKey.Key)
	if err != nil {
		klog.Error("Error encrypting the payload: " + err.Error())
	}

	signatureBase := make([]byte, 0, len(context.TransmissionKey.EncryptedKey)+len(encryptedPayload))
	signatureBase = append(signatureBase, ([]byte)(context.TransmissionKey.EncryptedKey)...)
	signatureBase = append(signatureBase, encryptedPayload...)

	if pk, err := DerBase64PrivateKeyToPrivateKey(c.Config.Get(KEY_PRIVATE_KEY)); err == nil {
		if signature, err := Sign(signatureBase, pk); err == nil {
			return EncryptedPayload{
				Payload:   encryptedPayload,
				Signature: signature,
			}, nil
		} else {
			return EncryptedPayload{}, errors.New("error generating signature: " + err.Error())
		}
	} else {
		return EncryptedPayload{}, errors.New("error loading private key: " + err.Error())
	}
}

func (c *SecretsManager) prepareGetPayload(context *Context, recordsFilter []string) (res EncryptedPayload, err error) {
	payload := GetPayload{
		ClientVersion: keeperSecretsManagerClientId,
		ClientId:      BytesToUrlSafeStr(context.ClientId),
	}

	if appKeyStr := c.Config.Get(KEY_APP_KEY); strings.TrimSpace(appKeyStr) == "" {
		if publicKeyBytes, err := extractPublicKeyBytes(c.Config.Get(KEY_PRIVATE_KEY)); err == nil {
			publicKeyBase64 := BytesToUrlSafeStr(publicKeyBytes)
			// passed once when binding
			payload.PublicKey = publicKeyBase64
		} else {
			return EncryptedPayload{}, errors.New("error extracting public key for get payload")
		}
	}

	if len(recordsFilter) > 0 {
		payload.RequestedRecords = recordsFilter
	}
	if payloadJson, err := payload.GetPayloadToJson(); err == nil {
		if encryptedPayload, err := c.encryptAndSignPayload(context, payloadJson); err == nil {
			return encryptedPayload, nil
		} else {
			return EncryptedPayload{}, errors.New("error encrypting get payload: " + err.Error())
		}
	} else {
		return EncryptedPayload{}, errors.New("error converting get payload to JSON: " + err.Error())
	}
}

func (c *SecretsManager) prepareUpdatePayload(context *Context, record *Record) (res *EncryptedPayload, err error) {
	payload := UpdatePayload{
		ClientVersion: keeperSecretsManagerClientId,
		ClientId:      BytesToUrlSafeStr(context.ClientId),
	}

	if len(context.ClientKey) < 1 {
		klog.Panicln("To save and update, client must be authenticated by device token only")
	}

	// for update, uid of the record
	payload.RecordUid = record.Uid
	payload.Revision = record.Revision

	// #TODO: This is where we need to get JSON of the updated Record
	rawJson := DictToJson(record.RecordDict)
	rawJsonBytes := StringToBytes(rawJson)
	if encryptedRawJsonBytes, err := EncryptAesGcm(rawJsonBytes, record.RecordKeyBytes); err == nil {
		// for create and update, the record data
		payload.Data = BytesToUrlSafeStr(encryptedRawJsonBytes)
	} else {
		return nil, err
	}

	if payloadJson, err := payload.UpdatePayloadToJson(); err == nil {
		if encryptedPayload, err := c.encryptAndSignPayload(context, payloadJson); err == nil {
			return &encryptedPayload, nil
		} else {
			return &EncryptedPayload{}, errors.New("error encrypting update payload: " + err.Error())
		}
	} else {
		return &EncryptedPayload{}, errors.New("error converting update payload to JSON: " + err.Error())
	}
}

func (c *SecretsManager) PostQuery(path string, context *Context, payloadAndSignature *EncryptedPayload) (*http.Response, []byte, error) {
	keeperServer := GetServerHostname(c.HostName, c.Config)

	transmissionKey := context.TransmissionKey
	payload := payloadAndSignature.Payload
	signature := payloadAndSignature.Signature

	url := fmt.Sprintf("https://%s/api/rest/sm/v1/%s", keeperServer, path)
	rq, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, nil, err
	}

	rq.Header.Set("Content-Type", "application/octet-stream")
	rq.Header.Set("Content-Length", fmt.Sprint(len(payload)))
	rq.Header.Set("PublicKeyId", transmissionKey.PublicKeyId)
	rq.Header.Set("TransmissionKey", BytesToUrlSafeStr(transmissionKey.EncryptedKey))
	rq.Header.Set("Authorization", fmt.Sprintf("Signature %s", BytesToUrlSafeStr(signature)))
	// klog.Debug(rq.Header)

	tr := http.DefaultClient.Transport
	if insecureSkipVerify := !c.VerifySslCerts; insecureSkipVerify {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
		}
	}
	client := &http.Client{Transport: tr}

	rs, err := client.Do(rq)
	if err != nil {
		return rs, nil, err
	}
	defer rs.Body.Close()

	rsBody, err := io.ReadAll(rs.Body)
	return rs, rsBody, err
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
		// This is a unknown error, not one of ours, just throw a HTTPError
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

func (c *SecretsManager) Fetch(recordFilter []string) (records []*Record, justBound bool, err error) {
	records = []*Record{}
	justBound = false
	var body []byte
	var context *Context

	for {
		context = c.PrepareContext()
		payloadAndSignature, err := c.prepareGetPayload(context, recordFilter)
		if err != nil {
			return records, justBound, err
		}

		var rs *http.Response
		rs, body, err = c.PostQuery("get_secret", context, &payloadAndSignature)

		if c.cache != nil {
			success := true
			if rs != nil && rs.StatusCode == 200 {
				data := append([]byte{}, context.TransmissionKey.Key...)
				c.cache.SaveCachedValue(append(data, body...))
			} else {
				if cachedData, cerr := c.cache.GetCachedValue(); cerr == nil && len(cachedData) >= Aes256KeySize {
					context.TransmissionKey.Key = cachedData[:Aes256KeySize]
					body = cachedData[Aes256KeySize:]
				} else {
					success = false
				}
			}
			if success {
				break
			}
		}

		if err != nil {
			return records, justBound, err
		}

		// If we are ok, then break out of the while loop
		if rs.StatusCode == 200 {
			break
		}

		// Handle the error. Handler will return a retry status if it is a recoverable error.
		if retry, err := c.HandleHttpError(rs, body, err); !retry {
			errMsg := "N/A"
			if err != nil {
				errMsg = err.Error()
			}
			klog.Panicln("Fetch Error: " + errMsg)
		}
	}

	decryptedResponseBytes, err := Decrypt(body, context.TransmissionKey.Key)
	if err != nil {
		return records, justBound, err
	}

	decryptedResponseStr := BytesToString(decryptedResponseBytes)
	decryptedResponseDict := JsonToDict(decryptedResponseStr)

	var secretKey []byte
	if encryptedAppKey, found := decryptedResponseDict["encryptedAppKey"]; found && encryptedAppKey != nil && fmt.Sprintf("%v", encryptedAppKey) != "" {
		justBound = true
		clientKey := c.Config.Get(KEY_CLIENT_KEY)
		if clientKey == "" {
			return records, justBound, errors.New("client key is missing from the storage")
		}
		encryptedMasterKey := UrlSafeStrToBytes(encryptedAppKey.(string))
		if secretKey, err = Decrypt(encryptedMasterKey, UrlSafeStrToBytes(clientKey)); err == nil {
			c.Config.Set(KEY_APP_KEY, BytesToUrlSafeStr(secretKey))
			c.Config.Delete(KEY_CLIENT_KEY)
		} else {
			klog.Error("failed to decrypt APP_KEY")
		}
	} else {
		secretKey = Base64ToBytes(c.Config.Get(KEY_APP_KEY))
		if len(secretKey) == 0 {
			return records, justBound, errors.New("app key is missing from the storage")
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
				record := NewRecordFromJson(r.(map[string]interface{}), secretKey)
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

	return records, justBound, nil
}

func (c *SecretsManager) GetSecrets(uids []string) (records []*Record, err error) {
	// Retrieve all records associated with the given application
	recordsResp, justBound, err := c.Fetch(uids)
	if err != nil {
		return nil, err
	}
	if justBound {
		recordsResp, _, err = c.Fetch(uids)
		if err != nil {
			return nil, err
		}
	}

	return recordsResp, nil
}

func (c *SecretsManager) Save(record *Record) (err error) {
	// Save updated secret values
	klog.Info("Updating record uid: " + record.Uid)

	for {
		context := c.PrepareContext()
		payloadAndSignature, err := c.prepareUpdatePayload(context, record)
		if err != nil {
			return err
		}

		rs, body, err := c.PostQuery("update_secret", context, payloadAndSignature)
		if err != nil {
			return err
		}

		// If we are ok, then break out of the while loop
		if rs.StatusCode == 200 {
			break
		}

		// Handle the error. Handler will return a retry status if it is a recoverable error.
		if retry, err := c.HandleHttpError(rs, body, err); !retry {
			errMsg := "N/A"
			if err != nil {
				errMsg = err.Error()
			}
			klog.Panicln("Save Error: " + errMsg)
		}
	}

	return nil
}

func (c *SecretsManager) GetNotation(url string) (fieldValue []interface{}, err error) {
	/*
		Simple string notation to get a value

		* A system of figures or symbols used in a specialized field to represent numbers, quantities, tones,
			or values.

		<uid>/<field|custom_field|file>/<label|type>[INDEX][FIELD]

		Example:

			EG6KdJaaLG7esRZbMnfbFA/field/password                => MyPasswprd
			EG6KdJaaLG7esRZbMnfbFA/field/password[0]             => MyPassword
			EG6KdJaaLG7esRZbMnfbFA/field/password[]              => ["MyPassword"]
			EG6KdJaaLG7esRZbMnfbFA/custom_field/name[first]      => John
			EG6KdJaaLG7esRZbMnfbFA/custom_field/name[last]       => Smitht
			EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[0][number] => "555-5555555"
			EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[1][number] => "777-7777777"
			EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[]          => [{"number": "555-555...}, { "number": "777.....}]
			EG6KdJaaLG7esRZbMnfbFA/custom_field/phone[0]         => [{"number": "555-555...}]
	*/

	fieldValue = []interface{}{}
	// If the URL starts with keeper:// we want to remove it.
	if strings.HasPrefix(strings.ToLower(url), c.NotationPrefix()) {
		errMisingPath := errors.New("keeper url missing information about the uid, field type, and field key")
		if urlParts := strings.Split(url, "//"); len(urlParts) > 1 {
			if url = urlParts[1]; url == "" {
				return fieldValue, errMisingPath
			}
		} else {
			return fieldValue, errMisingPath
		}
	}

	uid, fieldType, key := "", "", ""
	if urlParts := strings.Split(url, "/"); len(urlParts) == 3 {
		uid = urlParts[0]
		fieldType = urlParts[1]
		key = urlParts[2]
	} else {
		return fieldValue, fmt.Errorf("could not parse the notation '%s'. Is it valid? ", url)
	}

	if uid == "" {
		return fieldValue, errors.New("record UID is missing in the keeper url")
	}
	if fieldType == "" {
		return fieldValue, errors.New("field type is missing in the keeper url")
	}
	if key == "" {
		return fieldValue, errors.New("field key is missing in the keeper url")
	}

	// By default we want to return a single value, which is the first item in the array
	returnSingle := true
	index := 0
	dictKey := ""

	// Check it see if the key has a predicate, possibly with an index.
	rePredicate := regexp.MustCompile(`\[([^\]]*)\]`)
	rePredicateValue := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if predicates := rePredicate.FindAllStringSubmatch(key, 3); len(predicates) > 0 {
		if len(predicates) > 2 {
			return fieldValue, errors.New("the predicate of the notation appears to be invalid. Too many [], max 2 allowed. ")
		}
		if firstPredicate := predicates[0]; len(firstPredicate) > 1 {
			value := firstPredicate[1]
			// If the first predicate is an index into an array - fileRef[2]
			if i, err := strconv.ParseInt(value, 10, 64); err == nil {
				index = int(i)
			} else if matched := rePredicateValue.MatchString(value); matched {
				// the first predicate is a key to a dictionary - name[first]
				dictKey = value
			} else {
				// else it was an array indicator (.../name[] or .../name) - return all the values
				returnSingle = false
			}
		}
		if len(predicates) > 1 {
			if !returnSingle {
				return fieldValue, errors.New("if the second [] is a dictionary key, the first [] needs to have any index. ")
			}
			if secondPredicate := predicates[1]; len(secondPredicate) > 1 {
				if value := secondPredicate[1]; len(value) > 0 {
					// If the second predicate is an index into an array - fileRef[2]
					if _, err := strconv.ParseInt(value, 10, 64); err == nil {
						return fieldValue, errors.New("the second [] can only by a key for the dictionary. It cannot be an index. ")
					} else if matched := rePredicateValue.MatchString(value); matched {
						// the second predicate is a key to a dictionary - name[first]
						dictKey = value
					} else {
						// else it was an array indicator (.../name[] or .../name) - return all the values
						return fieldValue, errors.New("the second [] must have key for the dictionary. Cannot be blank. ")
					}
				}
			}
		}

		// Remove the predicate from the key, if it exists
		if pos := strings.Index(key, "["); pos >= 0 {
			key = key[:pos]
		}
	}

	records, err := c.GetSecrets([]string{uid})
	if err != nil {
		return fieldValue, err
	}
	if len(records) == 0 {
		return fieldValue, errors.New("Could not find a record with the UID " + uid)
	}

	record := records[0]

	var iValue []map[string]interface{}
	if fieldType == "field" {
		iValue = record.GetFieldsByType(key)
	} else if fieldType == "custom_field" {
		iValue = record.GetCustomFieldsByLabel(key) // by default custom[] searches are by label
	} else if fieldType == "file" {
		file := record.FindFileByTitle(key)
		if file == nil {
			return fieldValue, fmt.Errorf("cannot find the file %s in record %s. ", key, uid)
		}
		fieldValue = append(fieldValue, file.GetFileData())
		return fieldValue, nil
	} else {
		return fieldValue, fmt.Errorf("field type of %s is not value. ", fieldType)
	}

	if returnSingle {
		if len(iValue) == 0 {
			return fieldValue, nil
		}
		val, ok := iValue[0]["value"].([]interface{})
		if !ok {
			return fieldValue, nil
		}
		if len(val) > index {
			iVal := val[index]
			retMap, mapOk := iVal.(map[string]interface{})
			if mapOk && strings.TrimSpace(dictKey) != "" {
				if val, ok := retMap[dictKey]; ok {
					fieldValue = append(fieldValue, val)
				} else {
					return fieldValue, fmt.Errorf("cannot find the dictionary key %s in the value ", dictKey)
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
			return fieldValue, fmt.Errorf("the value at index %d does not exist for %s. ", index, url)
		}
	} else {
		fieldValue = append(fieldValue, iValue)
	}

	return fieldValue, nil
}
