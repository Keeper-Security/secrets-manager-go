package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math"
	"math/big"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

// ECDSASignature needed for compatibility with openssl (python > hazmat > openssl > ec > _ecdsa_sig_sign)
// which uses ASN.1/DER SEQUENCE format
// NB! MaxLen for ASN.1, depends on the encoding. P1363 only needs 64 bytes. And an OpePGP encoding only needs 66 bytes.
// ECDSASignature using ASN.1/DER needs up to 72 bytes. DER requires a minimum number of bytes.
// If ASN.1/BER is used, then the signature can be hundreds of bytes.
type ECDSASignature struct {
	R, S *big.Int
}

func GetOS() string {
	os := runtime.GOOS
	switch os {
	case "windows":
		return "Windows"
	case "darwin":
		return "MacOS"
	case "linux":
		return "Linux"
	default:
		return os
	}
}

func BytesToString(b []byte) string {
	return string(b)
}

func StringToBytes(s string) []byte {
	return []byte(s)
}

func ByteToInt(b []byte) string {
	return string(b)
}

func BytesToUrlSafeStr(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func UrlSafeStrToBytes(text string) []byte {
	text = strings.TrimRight(text, "=")
	// fix non URL Safe strings
	text = strings.ReplaceAll(text, "+", "-")
	text = strings.ReplaceAll(text, "/", "_")

	if result, err := base64.RawURLEncoding.DecodeString(text); err != nil {
		klog.Error("error converting base64 URL safe string to bytes - text: '" + text + "' - " + err.Error())
		return nil
	} else {
		return result
	}
}

func BytesToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64ToBytes(text string) []byte {
	return UrlSafeStrToBytes(text)
}

func Base64ToString(base64Text string) string {
	if bytes := UrlSafeStrToBytes(base64Text); len(bytes) > 0 {
		return BytesToString(bytes)
	}
	return ""
}

func GetRandomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	return data, err
}

func ClearBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func GenerateRandomBytes(size int) ([]byte, error) {
	return GetRandomBytes(size)
}

func GenerateUid() string {
	uid, _ := GetRandomBytes(16)
	return BytesToUrlSafeStr(uid)
}

func GenerateUidWithLength(bitLength int) string {
	if bitLength < 1 {
		return ""
	}

	bitmask := byte(0xFF)
	byteLength := bitLength / 8
	if bitLength%8 > 0 {
		byteLength++
		bitmask = byte(0x00)
		for i := 0; i < bitLength%8; i++ {
			bitmask |= (byte(0x01) << (7 - i))
		}
	}

	uid, _ := GetRandomBytes(byteLength)
	if bitmask != byte(0xFF) {
		uid = append(uid[:len(uid)-1], uid[len(uid)-1]&bitmask)
	}

	return BytesToUrlSafeStr(uid)
}

// UrlSafeSha256FromString generates URL safe encoded SHA256 sum of data in URL safe base64 encoded string
func UrlSafeSha256FromString(text string) string {
	if text == "" {
		return ""
	}

	bytes := UrlSafeStrToBytes(text)
	if len(bytes) == 0 {
		return ""
	}

	sha256 := sha256.Sum256(bytes)
	result := BytesToUrlSafeStr(sha256[:])
	return result
}

// Base64HmacFromString generates base64 encoded HMAC of the message string with the given key
func Base64HmacFromString(key []byte, message string) string {
	msgBytes := StringToBytes(message)
	hmac := HmacDigest(key, msgBytes)
	result := BytesToBase64(hmac)
	return result
}

func HmacDigest(key []byte, message []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	result := mac.Sum(nil)
	return result
}

func JsonToDict(content string) map[string]interface{} {
	var payload map[string]interface{}
	err := json.Unmarshal([]byte(content), &payload)
	if err != nil {
		klog.Error("Error parsing JSON: " + err.Error())
		return map[string]interface{}{}
	}
	return payload
}

func DictToJson(dict map[string]interface{}) string {
	content, err := json.Marshal(dict)
	if err != nil {
		klog.Error("Error converting to JSON: " + err.Error())
		return ""
	}
	return string(content)
}

func DictToJsonWithIndent(dict map[string]interface{}, indent string) string {
	content, err := json.MarshalIndent(dict, "", indent)
	if err != nil {
		klog.Error("Error converting to JSON: " + err.Error())
		return ""
	}
	return string(content)
}

func DictToJsonWithDefultIndent(dict map[string]interface{}) string {
	return DictToJsonWithIndent(dict, "    ")
}

func NowMilliseconds() int64 {
	// time.Now().UnixMilli() // requires go1.17+
	return time.Now().UnixNano() / int64(time.Millisecond)
}

var strToBoolMap = map[string]bool{
	"y":     true,
	"yes":   true,
	"t":     true,
	"true":  true,
	"on":    true,
	"1":     true,
	"n":     false,
	"no":    false,
	"f":     false,
	"false": false,
	"off":   false,
	"0":     false,
}

// StrToBool convert a string representation of truth to a boolean true or false.
func StrToBool(val string) (bool, error) {
	// true values are 'y', 'yes', 't', 'true', 'on', and '1'
	// false values are 'n', 'no', 'f', 'false', 'off', and '0'.
	val = strings.ToLower(val)
	if res, ok := strToBoolMap[val]; ok {
		return res, nil
	}
	return false, fmt.Errorf("invalid truth value %s", val)
}

// PathExists returns whether the given file or directory exists
func PathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}

func CloneByteSlice(src []byte) []byte {
	if src == nil {
		return nil
	} else {
		dst := make([]byte, len(src))
		copy(dst, src)
		return dst
	}
}

type CopyableMap map[string]interface{}
type CopyableSlice []interface{}

// DeepCopy will create a deep copy of this map.
// The depth of this copy is all inclusive.
// Both maps and slices will be considered when making the copy.
func (m CopyableMap) DeepCopy() map[string]interface{} {
	result := map[string]interface{}{}

	for k, v := range m {
		if mapvalue, isMap := v.(map[string]interface{}); isMap {
			result[k] = CopyableMap(mapvalue).DeepCopy()
			continue
		}

		if slicevalue, isSlice := v.([]interface{}); isSlice {
			result[k] = CopyableSlice(slicevalue).DeepCopy()
			continue
		}

		result[k] = v
	}

	return result
}

// DeepCopy will create a deep copy of this slice.
// The depth of this copy is all inclusive.
// Both maps and slices will be considered when making the copy.
func (s CopyableSlice) DeepCopy() []interface{} {
	result := []interface{}{}

	for _, v := range s {
		if mapvalue, isMap := v.(map[string]interface{}); isMap {
			result = append(result, CopyableMap(mapvalue).DeepCopy())
			continue
		}

		if slicevalue, isSlice := v.([]interface{}); isSlice {
			result = append(result, CopyableSlice(slicevalue).DeepCopy())
			continue
		}

		result = append(result, v)
	}

	return result
}

// Generate TOTP/HOTP codes - RFC 6238/RFC 4226

// TOTP represents Time-based OTP - https://datatracker.ietf.org/doc/html/rfc6238
type TOTP struct {
	Secret    string // Secret key (required)
	Digits    int    // OTP digit count (default: 6)
	Algorithm string // OTP Algorithm ("SHA1" or "SHA256" or "SHA512") (default: SHA1)
	Period    int64  // Period for which OTP is valid (seconds) (default: 30) == X in RFC6238
	UnixTime  int64  // (Optional) Unix Timestamp (default: Current unix timestamp)
}

// HOTP represents HMAC-Based OTP - https://datatracker.ietf.org/doc/html/rfc4226
type HOTP struct {
	Secret  string // Secret key (required)
	Digits  int    // OTP digit count (default: 6)
	Counter int64  // Counter value (default: 0)
}

// TotpCode provides detailed info about the generated TOTP code
type TotpCode struct {
	Code     string // TOTP Code
	TimeLeft int    // Time left in seconds (time before expiration)
	Period   int    // Period in seconds
}

// Generates TOTP code from the URL and returns OTP as string, seconds remaining and any error encountered.
func GetTotpCode(totpUrl string) (*TotpCode, error) {
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	// ex. otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30
	u, err := url.Parse(totpUrl)
	if err != nil || strings.ToLower(u.Scheme) != "otpauth" {
		return nil, errors.New("invalid TOTP URL: " + totpUrl)
	}
	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid TOTP URL query values: " + u.RawQuery)
	}

	secret := ""
	digits := 6
	algorithm := "SHA1"
	period := int64(30)

	// the only required parameter is the secret
	if value, ok := m["secret"]; ok {
		secret = strings.TrimSpace(value[0])
	}

	// fallback to defaults for optional parameters
	if value, ok := m["digits"]; ok {
		if d, err := strconv.Atoi(value[0]); err == nil {
			digits = d
		}
	}
	if value, ok := m["algorithm"]; ok && strings.TrimSpace(value[0]) != "" {
		algorithm = strings.TrimSpace(value[0])
	}
	if value, ok := m["period"]; ok {
		if d, err := strconv.Atoi(value[0]); err == nil {
			period = int64(d)
		}
	}

	totp := TOTP{
		Secret:    secret,
		Digits:    digits,
		Algorithm: algorithm,
		Period:    period,
	}

	if code, ttl, err := totp.Generate(); err == nil {
		return &TotpCode{
			Code:     code,
			TimeLeft: ttl,
			Period:   int(period),
		}, nil
	} else {
		return nil, err
	}
}

// Generates TOTP code and returns OTP as string, seconds remaining and any error encountered.
func (totp *TOTP) Generate() (code string, seconds int, err error) {
	var T0 int64 = 0 // initial counter time / start time
	var currentUnixTime int64

	if totp.Secret == "" {
		return "", 0, errors.New("TOTP secret key required")
	}

	if totp.Digits == 0 {
		totp.Digits = 6
	}

	if totp.Algorithm == "" {
		totp.Algorithm = "SHA1"
	}

	if totp.Period == 0 {
		totp.Period = 30
	}

	if totp.UnixTime != 0 {
		currentUnixTime = totp.UnixTime // get OTP at the given timestamp
	} else {
		currentUnixTime = time.Now().Unix() - T0 // get OTP at current timestamp
	}

	counter := currentUnixTime / totp.Period
	code, err = generateOTP(totp.Secret, counter, totp.Digits, totp.Algorithm)
	seconds = int(totp.Period - currentUnixTime%totp.Period)
	return
}

// Generates HOTP code and returns OTP as string and any error encountered.
func (hotp *HOTP) Generate() (string, error) {

	if hotp.Secret == "" {
		return "", errors.New("HOTP secret key required")
	}

	if hotp.Digits == 0 {
		hotp.Digits = 6
	}

	return generateOTP(hotp.Secret, hotp.Counter, hotp.Digits, "SHA1")
}

// Generates TOTP/HOTP code.
func generateOTP(base32Key string, counter int64, digits int, algo string) (string, error) {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter)) // convert counter to byte array
	rawBase32Key := strings.TrimRight(base32Key, "=")         // remove padding and use RawEncoding
	secretKey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(rawBase32Key)
	if err != nil {
		return "", errors.New("bad OTP secret key: " + err.Error())
	}

	var hasher hash.Hash
	switch strings.ToUpper(algo) {
	case "SHA1":
		hasher = hmac.New(sha1.New, secretKey)
	case "SHA256":
		hasher = hmac.New(sha256.New, secretKey)
	case "SHA512":
		hasher = hmac.New(sha512.New, secretKey)
	// although once part of Google Key Uri Format - https://github.com/google/google-authenticator/wiki/Key-Uri-Format/_history
	// removed MD5 as unreliable - only digests of length >= 20 can be used (MD5 has a digest length of 16)
	// case AlgorithmMD5:
	// 	hasher = md5.New()
	default:
		return "", errors.New("invalid OTP algorithm. Please use any one of SHA1/SHA256/SHA512")
	}

	if _, err = hasher.Write(counterBytes); err != nil {
		return "", errors.New("unable to compute HMAC: " + err.Error())
	}

	hash := hasher.Sum(nil)

	// truncate hash
	offset := hash[len(hash)-1] & 0x0F
	hash = hash[offset : offset+4]
	hash[0] = hash[0] & 0x7F

	decimal := binary.BigEndian.Uint32(hash)
	otp := decimal % uint32(math.Pow10(digits))

	result := strconv.Itoa(int(otp))
	if len(result) < digits {
		padded := strings.Repeat("0", digits) + result
		result = padded[len(padded)-digits:]
	}

	return result, nil
}

// Generate password
const AsciiLowercase string = "abcdefghijklmnopqrstuvwxyz"
const AsciiUppercase string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const AsciiDigits string = "0123456789"
const AsciiSpecialCharacters string = "\"!@#$%()+;<>=?[]{}^.,"

func randomSample(sampleLength int, sampleString string) (string, error) {
	if sampleLength > 0 && sampleString != "" {
		letters := []rune(sampleString)
		b := make([]rune, sampleLength)
		sampleStringLen := new(big.Int).SetInt64(int64(len(sampleString)))
		for i := range b {
			// Int returns a uniform random value in [0, max)
			r, err := rand.Int(rand.Reader, sampleStringLen)
			if err != nil {
				return "", fmt.Errorf("can't generate random value: %v, %v", i, err)
			}
			b[i] = letters[int(r.Int64())]
		}
		return string(b), nil
	}
	return "", nil
}

func shuffleString(text string) (string, error) {
	result := ""
	if text != "" {
		letters := []rune(text)
		for i := len(letters) - 1; i >= 1; i-- {
			n := new(big.Int).SetInt64(int64(i + 1))
			// Int returns a uniform random value in [0, max)
			bj, err := rand.Int(rand.Reader, n) // 0 <= j <= i
			if err != nil {
				return "", fmt.Errorf("can't generate random value: %v, %v", i, err)
			}
			if j := int(bj.Int64()); i != j {
				letters[i], letters[j] = letters[j], letters[i]
			}
		}
		return string(letters), nil
	}
	return result, nil
}

func GeneratePassword(length, lowercase, uppercase, digits, specialCharacters int) (string, error) {
	if length <= 0 {
		length = 64
	}
	if lowercase == 0 && uppercase == 0 && digits == 0 && specialCharacters == 0 {
		increment := length / 4
		lastincrement := increment + (length % 4)
		lowercase, uppercase, digits = increment, increment, increment
		specialCharacters = lastincrement
	}

	passwordCharacters := ""
	if lowercase > 0 {
		if sample, err := randomSample(lowercase, AsciiLowercase); err == nil {
			passwordCharacters += sample
		} else {
			return passwordCharacters, err
		}
	}
	if uppercase > 0 {
		if sample, err := randomSample(uppercase, AsciiUppercase); err == nil {
			passwordCharacters += sample
		} else {
			return passwordCharacters, err
		}
	}
	if digits > 0 {
		if sample, err := randomSample(digits, AsciiDigits); err == nil {
			passwordCharacters += sample
		} else {
			return passwordCharacters, err
		}
	}
	if specialCharacters > 0 {
		if sample, err := randomSample(specialCharacters, AsciiSpecialCharacters); err == nil {
			passwordCharacters += sample
		} else {
			return passwordCharacters, err
		}
	}

	return shuffleString(passwordCharacters)
}
