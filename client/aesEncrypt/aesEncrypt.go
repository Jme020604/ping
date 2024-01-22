package aesEncrypt

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"log"
)

func EncryptAES(key []byte, plaintext string) string {

	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintextBytes := []byte(plaintext)
	plaintextResult := PKCS7Padding(plaintextBytes)
	plaintext = string(plaintextResult)

	out := make([]byte, len(plaintext))

	c.Encrypt(out, []byte(plaintext))

	return hex.EncodeToString(out)
}

func DecryptAES(key []byte, ct string) string {
	ciphertext, err := hex.DecodeString(ct)
	if err != nil {
		log.Fatal("error decoding hex string: ", err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("error creating AES cipher: ", err)
	}

	// Ensure the ciphertext length is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		log.Fatal("ciphertext length is not a multiple of the block size")
	}

	pt := make([]byte, len(ciphertext))
	c.Decrypt(pt, ciphertext)

	// Remove PKCS7 padding
	pt = PKCS7UnPadding(pt)

	return string(pt)
}

func PKCS7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	if length == 0 {
		return nil
	}
	unpadding := int(plantText[length-1])
	if unpadding > length {
		return nil // or handle the invalid unpadding value accordingly
	}
	return plantText[:(length - unpadding)]
}
