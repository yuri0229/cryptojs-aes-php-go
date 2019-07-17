package mcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"time"
)

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func base64Decode(str string) (string, error) {
	switch len(str) % 4 {
	case 2:
		str += "=="
	case 3:
		str += "="
	}

	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func pkcs7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext) % aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs7UnPadding(plantText []byte) []byte {
	length   := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

func hexMd5(str string) string {
	hash := md5.New()
	hash.Write([]byte(str))
	md5Str := hex.EncodeToString(hash.Sum(nil))
	_s,_ := hex.DecodeString(md5Str)
	return string(_s)
}

func randBytes(length int) []byte {
	buf := bytes.Buffer{}
	rand.Seed(int64(time.Now().UnixNano()))
	for i:=0; i<length; i++ {
		buf.WriteByte(byte(func(min int , max int) int {
			return min + rand.Intn(max-min)
		}(1, 250)))
	}
	return buf.Bytes()
}

type jsonData struct {
	Ct	string	`json:"ct"`
	Iv 	string	`json:"iv"`
	S 	string	`json:"s"`
}

func CryptoJsAesDecrypt(passphrase, jsonString string) string {
	jsonData := jsonData{}
	json.Unmarshal([]byte(jsonString), &jsonData)
	salt,_ := hex.DecodeString(jsonData.S)
	iv,_ := hex.DecodeString(jsonData.Iv)
	ct,_ := base64Decode(jsonData.Ct)
	concatedPassphrase := passphrase+string(salt)
	md5 := make(map[int]string, 3)
	md5[0] = hexMd5(concatedPassphrase)
	result := md5[0]
	for i:=1; i<3; i++ {
		md5[i] = hexMd5(md5[i-1]+concatedPassphrase)
		result += md5[i]
	}
	key,_ := hex.DecodeString(result)
	key = key[0:32]
	aesCipher, err := decrypt([]byte(key), iv, []byte(ct),  "rijndael-128", "cbc")
	if err != nil {
		return ""
	}
	return string(pkcs7UnPadding(aesCipher))
}

func CryptoJsAesEncrypt(passphrase, value string) string {
	var (
		salt, salted, dx, key, iv string
	)
	salt = string(randBytes(8))
	for len(salted) < 48 {
		dx = hexMd5(dx+passphrase+salt)
		salted += dx
	}
	key = salted[0:32]
	iv = salted[31:47]
	p7Value := pkcs7Padding([]byte(value))
	encrypted_data,_ := encrypt([]byte(key), []byte(iv), p7Value, "rijndael-128", "cbc")
	jsonData := jsonData{
		Ct: string(base64Encode(encrypted_data)),
		Iv: hex.EncodeToString([]byte(iv)),
		S: hex.EncodeToString([]byte(salt)),
	}
	json,_ := json.Marshal(jsonData)
	return string(json)
}