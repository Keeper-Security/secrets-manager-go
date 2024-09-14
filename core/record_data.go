package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

type KeeperRecordData struct {
	Type   string              `json:"type,omitempty"`
	Title  string              `json:"title,omitempty"`
	Notes  string              `json:"notes,omitempty"`
	Fields []KeeperRecordField `json:"fields,omitempty"`
	Custom []KeeperRecordField `json:"custom,omitempty"`
}

type KeeperRecordField struct {
	Type  string `json:"type"`
	Label string `json:"label,omitempty"`
}

type Login struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewLogin(value string) *Login {
	return &Login{
		KeeperRecordField: KeeperRecordField{Type: "login"},
		Value:             []string{value},
	}
}

type PasswordComplexity struct {
	Length    int `json:"length,omitempty"`
	Caps      int `json:"caps,omitempty"`
	Lowercase int `json:"lowercase,omitempty"`
	Digits    int `json:"digits,omitempty"`
	Special   int `json:"special,omitempty"`
}

type Password struct {
	KeeperRecordField
	Required          bool                `json:"required,omitempty"`
	PrivacyScreen     bool                `json:"privacyScreen,omitempty"`
	EnforceGeneration bool                `json:"enforceGeneration,omitempty"`
	Complexity        *PasswordComplexity `json:"complexity,omitempty"`
	Value             []string            `json:"value,omitempty"`
}

func NewPassword(value string) *Password {
	return &Password{
		KeeperRecordField: KeeperRecordField{Type: "password"},
		Value:             []string{value},
	}
}

type Url struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewUrl(value string) *Url {
	return &Url{
		KeeperRecordField: KeeperRecordField{Type: "url"},
		Value:             []string{value},
	}
}

// "file" - obsolete and removed legacy field - "fldt_file": { key: 'file_or_photo', default: "File or Photo" },
type FileRef struct {
	KeeperRecordField
	Required bool     `json:"required,omitempty"`
	Value    []string `json:"value,omitempty"`
}

func NewFileRef(value string) *FileRef {
	return &FileRef{
		KeeperRecordField: KeeperRecordField{Type: "fileRef"},
		Value:             []string{value},
	}
}

type OneTimeCode struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewOneTimeCode(value string) *OneTimeCode {
	return &OneTimeCode{
		KeeperRecordField: KeeperRecordField{Type: "oneTimeCode"},
		Value:             []string{value},
	}
}

type OneTimePassword struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewOneTimePassword(value string) *OneTimePassword {
	return &OneTimePassword{
		KeeperRecordField: KeeperRecordField{Type: "otp"},
		Value:             []string{value},
	}
}

type Name struct {
	First  string `json:"first,omitempty"`
	Middle string `json:"middle,omitempty"`
	Last   string `json:"last,omitempty"`
}

type Names struct {
	KeeperRecordField
	Required      bool   `json:"required,omitempty"`
	PrivacyScreen bool   `json:"privacyScreen,omitempty"`
	Value         []Name `json:"value,omitempty"`
}

func NewNames(value Name) *Names {
	return &Names{
		KeeperRecordField: KeeperRecordField{Type: "name"},
		Value:             []Name{value},
	}
}

type BirthDate struct {
	KeeperRecordField
	Required      bool    `json:"required,omitempty"`
	PrivacyScreen bool    `json:"privacyScreen,omitempty"`
	Value         []int64 `json:"value,omitempty"`
}

func NewBirthDate(value int64) *BirthDate {
	return &BirthDate{
		KeeperRecordField: KeeperRecordField{Type: "birthDate"},
		Value:             []int64{value},
	}
}

type Date struct {
	KeeperRecordField
	Required      bool    `json:"required,omitempty"`
	PrivacyScreen bool    `json:"privacyScreen,omitempty"`
	Value         []int64 `json:"value,omitempty"`
}

func NewDate(value int64) *Date {
	return &Date{
		KeeperRecordField: KeeperRecordField{Type: "date"},
		Value:             []int64{value},
	}
}

type ExpirationDate struct {
	KeeperRecordField
	Required      bool    `json:"required,omitempty"`
	PrivacyScreen bool    `json:"privacyScreen,omitempty"`
	Value         []int64 `json:"value,omitempty"`
}

func NewExpirationDate(value int64) *ExpirationDate {
	return &ExpirationDate{
		KeeperRecordField: KeeperRecordField{Type: "expirationDate"},
		Value:             []int64{value},
	}
}

type Text struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewText(value string) *Text {
	return &Text{
		KeeperRecordField: KeeperRecordField{Type: "text"},
		Value:             []string{value},
	}
}

type SecurityQuestion struct {
	Question string `json:"question,omitempty"`
	Answer   string `json:"answer,omitempty"`
}

type SecurityQuestions struct {
	KeeperRecordField
	Required      bool               `json:"required,omitempty"`
	PrivacyScreen bool               `json:"privacyScreen,omitempty"`
	Value         []SecurityQuestion `json:"value,omitempty"`
}

func NewSecurityQuestions(value SecurityQuestion) *SecurityQuestions {
	return &SecurityQuestions{
		KeeperRecordField: KeeperRecordField{Type: "securityQuestion"},
		Value:             []SecurityQuestion{value},
	}
}

type Multiline struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewMultiline(value string) *Multiline {
	return &Multiline{
		KeeperRecordField: KeeperRecordField{Type: "multiline"},
		Value:             []string{value},
	}
}

type Email struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewEmail(value string) *Email {
	return &Email{
		KeeperRecordField: KeeperRecordField{Type: "email"},
		Value:             []string{value},
	}
}

type CardRef struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewCardRef(value string) *CardRef {
	return &CardRef{
		KeeperRecordField: KeeperRecordField{Type: "cardRef"},
		Value:             []string{value},
	}
}

type AddressRef struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewAddressRef(value string) *AddressRef {
	return &AddressRef{
		KeeperRecordField: KeeperRecordField{Type: "addressRef"},
		Value:             []string{value},
	}
}

type PinCode struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewPinCode(value string) *PinCode {
	return &PinCode{
		KeeperRecordField: KeeperRecordField{Type: "pinCode"},
		Value:             []string{value},
	}
}

type Phone struct {
	Region string `json:"region,omitempty"` // Region code. Ex. US
	Number string `json:"number,omitempty"` // Phone number. Ex. 510-222-5555
	Ext    string `json:"ext,omitempty"`    // Extension number. Ex. 9987
	Type   string `json:"type,omitempty"`   // Phone number type. Ex. Mobile
}

type Phones struct {
	KeeperRecordField
	Required      bool    `json:"required,omitempty"`
	PrivacyScreen bool    `json:"privacyScreen,omitempty"`
	Value         []Phone `json:"value,omitempty"`
}

func NewPhones(value Phone) *Phones {
	return &Phones{
		KeeperRecordField: KeeperRecordField{Type: "phone"},
		Value:             []Phone{value},
	}
}

type Secret struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewSecret(value string) *Secret {
	return &Secret{
		KeeperRecordField: KeeperRecordField{Type: "secret"},
		Value:             []string{value},
	}
}

type SecureNote struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewSecureNote(value string) *SecureNote {
	return &SecureNote{
		KeeperRecordField: KeeperRecordField{Type: "note"},
		Value:             []string{value},
	}
}

type AccountNumber struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewAccountNumber(value string) *AccountNumber {
	return &AccountNumber{
		KeeperRecordField: KeeperRecordField{Type: "accountNumber"},
		Value:             []string{value},
	}
}

type PaymentCard struct {
	CardNumber         string `json:"cardNumber,omitempty"`
	CardExpirationDate string `json:"cardExpirationDate,omitempty"`
	CardSecurityCode   string `json:"cardSecurityCode,omitempty"`
}

type PaymentCards struct {
	KeeperRecordField
	Required      bool          `json:"required,omitempty"`
	PrivacyScreen bool          `json:"privacyScreen,omitempty"`
	Value         []PaymentCard `json:"value,omitempty"`
}

func NewPaymentCards(value PaymentCard) *PaymentCards {
	return &PaymentCards{
		KeeperRecordField: KeeperRecordField{Type: "paymentCard"},
		Value:             []PaymentCard{value},
	}
}

type BankAccount struct {
	AccountType   string `json:"accountType,omitempty"`
	RoutingNumber string `json:"routingNumber,omitempty"`
	AccountNumber string `json:"accountNumber,omitempty"`
	OtherType     string `json:"otherType,omitempty"`
}

type BankAccounts struct {
	KeeperRecordField
	Required      bool          `json:"required,omitempty"`
	PrivacyScreen bool          `json:"privacyScreen,omitempty"`
	Value         []BankAccount `json:"value,omitempty"`
}

func NewBankAccounts(value BankAccount) *BankAccounts {
	return &BankAccounts{
		KeeperRecordField: KeeperRecordField{Type: "bankAccount"},
		Value:             []BankAccount{value},
	}
}

type KeyPair struct {
	PublicKey  string `json:"publicKey,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
}

type KeyPairs struct {
	KeeperRecordField
	Required      bool      `json:"required,omitempty"`
	PrivacyScreen bool      `json:"privacyScreen,omitempty"`
	Value         []KeyPair `json:"value,omitempty"`
}

func NewKeyPairs(value KeyPair) *KeyPairs {
	return &KeyPairs{
		KeeperRecordField: KeeperRecordField{Type: "keyPair"},
		Value:             []KeyPair{value},
	}
}

type Host struct {
	Hostname string `json:"hostName,omitempty"`
	Port     string `json:"port,omitempty"`
}

type Hosts struct {
	KeeperRecordField
	Required      bool   `json:"required,omitempty"`
	PrivacyScreen bool   `json:"privacyScreen,omitempty"`
	Value         []Host `json:"value,omitempty"`
}

func NewHosts(value Host) *Hosts {
	return &Hosts{
		KeeperRecordField: KeeperRecordField{Type: "host"},
		Value:             []Host{value},
	}
}

type Address struct {
	Street1 string `json:"street1,omitempty"`
	Street2 string `json:"street2,omitempty"`
	City    string `json:"city,omitempty"`
	State   string `json:"state,omitempty"`
	Country string `json:"country,omitempty"`
	Zip     string `json:"zip,omitempty"`
}

type Addresses struct {
	KeeperRecordField
	Required      bool      `json:"required,omitempty"`
	PrivacyScreen bool      `json:"privacyScreen,omitempty"`
	Value         []Address `json:"value,omitempty"`
}

func NewAddresses(value Address) *Addresses {
	return &Addresses{
		KeeperRecordField: KeeperRecordField{Type: "address"},
		Value:             []Address{value},
	}
}

type LicenseNumber struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []string `json:"value,omitempty"`
}

func NewLicenseNumber(value string) *LicenseNumber {
	return &LicenseNumber{
		KeeperRecordField: KeeperRecordField{Type: "licenseNumber"},
		Value:             []string{value},
	}
}

type RecordRef struct {
	KeeperRecordField
	Required bool     `json:"required,omitempty"`
	Value    []string `json:"value,omitempty"`
}

func NewRecordRef(value string) *RecordRef {
	return &RecordRef{
		KeeperRecordField: KeeperRecordField{Type: "recordRef"},
		Value:             []string{value},
	}
}

type Schedule struct {
	Type string `json:"type,omitempty"`
	Cron string `json:"cron,omitempty"`
	// UtcTime - replaced by time and tz
	Time          string `json:"time,omitempty"`
	Tz            string `json:"tz,omitempty"`
	Weekday       string `json:"weekday,omitempty"`
	IntervalCount int    `json:"intervalCount,omitempty"`
}

type Schedules struct {
	KeeperRecordField
	Required bool       `json:"required,omitempty"`
	Value    []Schedule `json:"value,omitempty"`
}

func NewSchedules(value Schedule) *Schedules {
	return &Schedules{
		KeeperRecordField: KeeperRecordField{Type: "schedule"},
		Value:             []Schedule{value},
	}
}

type DirectoryType struct {
	KeeperRecordField
	Required bool     `json:"required,omitempty"`
	Value    []string `json:"value,omitempty"`
}

func NewDirectoryType(value string) *DirectoryType {
	return &DirectoryType{
		KeeperRecordField: KeeperRecordField{Type: "directoryType"},
		Value:             []string{value},
	}
}

type DatabaseType struct {
	KeeperRecordField
	Required bool     `json:"required,omitempty"`
	Value    []string `json:"value,omitempty"`
}

func NewDatabaseType(value string) *DatabaseType {
	return &DatabaseType{
		KeeperRecordField: KeeperRecordField{Type: "databaseType"},
		Value:             []string{value},
	}
}

type PamHostname struct {
	KeeperRecordField
	Required      bool   `json:"required,omitempty"`
	PrivacyScreen bool   `json:"privacyScreen,omitempty"`
	Value         []Host `json:"value,omitempty"`
}

func NewPamHostname(value Host) *PamHostname {
	return &PamHostname{
		KeeperRecordField: KeeperRecordField{Type: "pamHostname"},
		Value:             []Host{value},
	}
}

type AllowedSettings struct {
	Connections         bool `json:"connections,omitempty"`
	PortForwards        bool `json:"portForwards,omitempty"`
	Rotation            bool `json:"rotation,omitempty"`
	SessionRecording    bool `json:"sessionRecording,omitempty"`
	TypescriptRecording bool `json:"typescriptRecording,omitempty"`
}

type PamResource struct {
	ControllerUid   string          `json:"controllerUid,omitempty"`
	FolderUid       string          `json:"folderUid,omitempty"`
	ResourceRef     []string        `json:"resourceRef,omitempty"`
	AllowedSettings AllowedSettings `json:"allowedSettings,omitempty"`
}

type PamResources struct {
	KeeperRecordField
	Required bool          `json:"required,omitempty"`
	Value    []PamResource `json:"value,omitempty"`
}

func NewPamResources(value PamResource) *PamResources {
	return &PamResources{
		KeeperRecordField: KeeperRecordField{Type: "pamResources"},
		Value:             []PamResource{value},
	}
}

type Checkbox struct {
	KeeperRecordField
	Required bool   `json:"required,omitempty"`
	Value    []bool `json:"value,omitempty"`
}

func NewCheckbox(value bool) *Checkbox {
	return &Checkbox{
		KeeperRecordField: KeeperRecordField{Type: "checkbox"},
		Value:             []bool{value},
	}
}

type Script struct {
	FileRef   string   `json:"fileRef,omitempty"`
	Command   string   `json:"command,omitempty"`
	RecordRef []string `json:"recordRef,omitempty"`
}

type Scripts struct {
	KeeperRecordField
	Required      bool     `json:"required,omitempty"`
	PrivacyScreen bool     `json:"privacyScreen,omitempty"`
	Value         []Script `json:"value,omitempty"`
}

func NewScripts(value Script) *Scripts {
	return &Scripts{
		KeeperRecordField: KeeperRecordField{Type: "script"},
		Value:             []Script{value},
	}
}

type PasskeyPrivateKey struct {
	Crv    string   `json:"crv,omitempty"`
	D      string   `json:"d,omitempty"`
	Ext    bool     `json:"ext,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Kty    string   `json:"kty,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      int64    `json:"y,omitempty"`
}

type Passkey struct {
	PrivateKey   PasskeyPrivateKey `json:"privateKey,omitempty"`
	CredentialId string            `json:"credentialId,omitempty"`
	SignCount    int64             `json:"signCount,omitempty"`
	UserId       string            `json:"userId,omitempty"`
	RelyingParty string            `json:"relyingParty,omitempty"`
	Username     string            `json:"username,omitempty"`
	CreatedDate  int64             `json:"createdDate,omitempty"`
}

type Passkeys struct {
	KeeperRecordField
	Required bool      `json:"required,omitempty"`
	Value    []Passkey `json:"value,omitempty"`
}

func NewPasskeys(value Passkey) *Passkeys {
	return &Passkeys{
		KeeperRecordField: KeeperRecordField{Type: "passkey"},
		Value:             []Passkey{value},
	}
}

type IsSsidHidden struct {
	KeeperRecordField
	Required bool   `json:"required,omitempty"`
	Value    []bool `json:"value,omitempty"`
}

func NewIsSsidHidden(value bool) *IsSsidHidden {
	return &IsSsidHidden{
		KeeperRecordField: KeeperRecordField{Type: "isSSIDHidden"},
		Value:             []bool{value},
	}
}

type WifiEncryption struct {
	KeeperRecordField
	Required bool     `json:"required,omitempty"`
	Value    []string `json:"value,omitempty"`
}

func NewWifiEncryption(value string) *WifiEncryption {
	return &WifiEncryption{
		KeeperRecordField: KeeperRecordField{Type: "wifiEncryption"},
		Value:             []string{value},
	}
}

type Dropdown struct {
	KeeperRecordField
	Required bool     `json:"required,omitempty"`
	Value    []string `json:"value,omitempty"`
}

func NewDropdown(value string) *Dropdown {
	return &Dropdown{
		KeeperRecordField: KeeperRecordField{Type: "dropdown"},
		Value:             []string{value},
	}
}

type RbiUrl struct {
	KeeperRecordField
	Required bool     `json:"required,omitempty"`
	Value    []string `json:"value,omitempty"`
}

func NewRbiUrl(value string) *RbiUrl {
	return &RbiUrl{
		KeeperRecordField: KeeperRecordField{Type: "rbiUrl"},
		Value:             []string{value},
	}
}

type AppFiller struct {
	ApplicationTitle string `json:"applicationTitle,omitempty"`
	ContentFilter    string `json:"contentFilter,omitempty"`
	MacroSequence    string `json:"macroSequence,omitempty"`
}

type AppFillers struct {
	KeeperRecordField
	Required      bool        `json:"required,omitempty"`
	PrivacyScreen bool        `json:"privacyScreen,omitempty"`
	Value         []AppFiller `json:"value,omitempty"`
}

func NewAppFillers(value AppFiller) *AppFillers {
	return &AppFillers{
		KeeperRecordField: KeeperRecordField{Type: "appFiller"},
		Value:             []AppFiller{value},
	}
}

type PamRbiConnection struct {
	Protocol                   string   `json:"protocol,omitempty"`
	Enabled                    bool     `json:"enabled,omitempty"`
	UserRecords                []string `json:"user_records,omitempty"`
	AllowUrlManipulation       bool     `json:"allow-url-manipulation,omitempty"`
	AllowedUrlPatterns         string   `json:"allowed-url-patterns,omitempty"`
	AllowedResourceUrlPatterns string   `json:"allowed-resource-url-patterns,omitempty"`
	HttpCredentialsUid         string   `json:"http-credentials-uid,omitempty"`
	AutofillConfiguration      string   `json:"autofill-configuration,omitempty"`
}

type PamRemoteBrowserSetting struct {
	Connection PamRbiConnection `json:"connection,omitempty"`
}

type PamRemoteBrowserSettings struct {
	KeeperRecordField
	Required bool                      `json:"required,omitempty"`
	Value    []PamRemoteBrowserSetting `json:"value,omitempty"`
}

func NewPamRemoteBrowserSettings(value PamRemoteBrowserSetting) *PamRemoteBrowserSettings {
	return &PamRemoteBrowserSettings{
		KeeperRecordField: KeeperRecordField{Type: "pamRemoteBrowserSettings"},
		Value:             []PamRemoteBrowserSetting{value},
	}
}

type PamSettingsPortForward struct {
	Enabled   bool   `json:"enabled,omitempty"`
	ReusePort bool   `json:"reusePort,omitempty"`
	Port      string `json:"port,omitempty"`
}

type PamSettingsConnection struct {
	Protocol     string   `json:"protocol,omitempty"`
	Enabled      bool     `json:"enabled,omitempty"`
	UserRecords  []string `json:"user_records,omitempty"`
	Security     string   `json:"security,omitempty"`
	IgnoreCert   bool     `json:"ignore-cert,omitempty"`
	ResizeMethod string   `json:"resize-method,omitempty"`
	ColorScheme  string   `json:"color-scheme,omitempty"`
}

type PamSetting struct {
	ConfigUid          string                   `json:"configUid,omitempty"`
	AdminCredentialUid string                   `json:"adminCredentialUid,omitempty"`
	PortForward        []PamSettingsPortForward `json:"portForward,omitempty"`
	Connection         []PamSettingsConnection  `json:"connection,omitempty"`
}

type PamSettings struct {
	KeeperRecordField
	Required bool         `json:"required,omitempty"`
	Value    []PamSetting `json:"value,omitempty"`
}

func NewPamSettings(value PamSetting) *PamSettings {
	return &PamSettings{
		KeeperRecordField: KeeperRecordField{Type: "pamSettings"},
		Value:             []PamSetting{value},
	}
}

type TrafficEncryptionSeed struct {
	KeeperRecordField
	Required bool     `json:"required,omitempty"`
	Value    []string `json:"value,omitempty"`
}

func NewTrafficEncryptionSeed(value string) *TrafficEncryptionSeed {
	return &TrafficEncryptionSeed{
		KeeperRecordField: KeeperRecordField{Type: "trafficEncryptionSeed"},
		Value:             []string{value},
	}
}

// List of retired field types:
// trafficEncryptionKey - replaced by trafficEncryptionSeed
// pamProvider - deprecated for legacy/internal use only
// controller - deprecated for legacy/internal use only

// getKeeperRecordField converts fieldData from generic interface{} to strongly typed interface{}
func getKeeperRecordField(fieldType string, fieldData map[string]interface{}, validate bool) (field interface{}, err error) {
	if jsonField := DictToJson(fieldData); strings.TrimSpace(jsonField) != "" {
		switch fieldType {
		case "accountNumber":
			field = &AccountNumber{}
		case "address":
			field = &Addresses{}
		case "addressRef":
			field = &AddressRef{}
		case "appFiller":
			field = &AppFillers{}
		case "bankAccount":
			field = &BankAccounts{}
		case "birthDate":
			field = &BirthDate{}
		case "cardRef":
			field = &CardRef{}
		case "checkbox":
			field = &Checkbox{}
		case "databaseType":
			field = &DatabaseType{}
		case "date":
			field = &Date{}
		case "directoryType":
			field = &DirectoryType{}
		case "dropdown":
			field = &Dropdown{}
		case "email":
			field = &Email{}
		case "expirationDate":
			field = &ExpirationDate{}
		case "fileRef":
			field = &FileRef{}
		case "host":
			field = &Hosts{}
		case "isSSIDHidden":
			field = &IsSsidHidden{}
		case "keyPair":
			field = &KeyPairs{}
		case "licenseNumber":
			field = &LicenseNumber{}
		case "login":
			field = &Login{}
		case "multiline":
			field = &Multiline{}
		case "name":
			field = &Names{}
		case "note":
			field = &SecureNote{}
		case "oneTimeCode":
			field = &OneTimeCode{}
		case "otp":
			field = &OneTimePassword{}
		case "pamHostname":
			field = &PamHostname{}
		case "pamRemoteBrowserSettings":
			field = &PamRemoteBrowserSettings{}
		case "pamResources":
			field = &PamResources{}
		case "pamSettings":
			field = &PamSettings{}
		case "passkey":
			field = &Passkeys{}
		case "password":
			field = &Password{}
		case "paymentCard":
			field = &PaymentCards{}
		case "phone":
			field = &Phones{}
		case "pinCode":
			field = &PinCode{}
		case "rbiUrl":
			field = &RbiUrl{}
		case "recordRef":
			field = &RecordRef{}
		case "schedule":
			field = &Schedules{}
		case "script":
			field = &Scripts{}
		case "secret":
			field = &Secret{}
		case "securityQuestion":
			field = &SecurityQuestions{}
		case "text":
			field = &Text{}
		case "trafficEncryptionSeed":
			field = &TrafficEncryptionSeed{}
		case "url":
			field = &Url{}
		case "wifiEncryption":
			field = &WifiEncryption{}
		default:
			return nil, fmt.Errorf("unable to convert unknown field type %v", fieldType)
		}

		if validate {
			decoder := json.NewDecoder(strings.NewReader(jsonField))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(field)
		} else {
			err = json.Unmarshal([]byte(jsonField), field)
		}
		return
	} else {
		return nil, fmt.Errorf("unable to parse field from JSON '%v'", fieldData)
	}
}

func IsFieldClass(field interface{}) bool {
	switch field.(type) {
	case
		AccountNumber, *AccountNumber,
		Addresses, *Addresses,
		AddressRef, *AddressRef,
		AppFillers, *AppFillers,
		BankAccounts, *BankAccounts,
		BirthDate, *BirthDate,
		CardRef, *CardRef,
		Checkbox, *Checkbox,
		DatabaseType, *DatabaseType,
		Date, *Date,
		DirectoryType, *DirectoryType,
		Dropdown, *Dropdown,
		Email, *Email,
		ExpirationDate, *ExpirationDate,
		FileRef, *FileRef,
		Hosts, *Hosts,
		IsSsidHidden, *IsSsidHidden,
		KeyPairs, *KeyPairs,
		LicenseNumber, *LicenseNumber,
		Login, *Login,
		Multiline, *Multiline,
		Names, *Names,
		OneTimeCode, *OneTimeCode,
		OneTimePassword, *OneTimePassword,
		PamHostname, *PamHostname,
		PamRemoteBrowserSettings, *PamRemoteBrowserSettings,
		PamResources, *PamResources,
		PamSettings, *PamSettings,
		Passkeys, *Passkeys,
		Password, *Password,
		PaymentCards, *PaymentCards,
		Phones, *Phones,
		PinCode, *PinCode,
		RbiUrl, *RbiUrl,
		RecordRef, *RecordRef,
		Schedules, *Schedules,
		Scripts, *Scripts,
		Secret, *Secret,
		SecureNote, *SecureNote,
		SecurityQuestions, *SecurityQuestions,
		Text, *Text,
		TrafficEncryptionSeed, *TrafficEncryptionSeed,
		Url, *Url,
		WifiEncryption, *WifiEncryption:
		return true
	}
	return false
}

func structToMap(data interface{}) (map[string]interface{}, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	mapData := make(map[string]interface{})
	err = json.Unmarshal(dataBytes, &mapData)
	if err != nil {
		return nil, err
	}
	return mapData, nil
}
