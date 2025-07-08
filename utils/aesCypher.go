package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	b64 "encoding/base64"
	"io"
	"os"

	"github.com/rs/zerolog/log"
)

// Environment variable is not a safe place to store keys, but this fits for an example https://security.stackexchange.com/questions/12332/where-to-store-a-server-side-encryption-key/12334#12334

// Returns base64 aes-encrypted string
func EncryptAES(rawString string) string {
	block, err := aes.NewCipher([]byte(os.Getenv("AES_KEY")))
	if err != nil {
		log.Error().Msgf("Error occured while creating new cipher %v", err)
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Error().Msgf("Error occured while encrypting %v", err)
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Error().Msgf("Error occured while generating nonce %v", err)
		return ""
	}

	result := b64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(rawString), nil))

	return result
}

func DecryptAES(encryptedString string) string {
	strFromB64, _ := b64.StdEncoding.DecodeString(encryptedString)
	block, err := aes.NewCipher([]byte(os.Getenv("AES_KEY")))
	if err != nil {
		log.Error().Msgf("Error occured while decrypting %v", err)
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Error().Msgf("Error occured while decrypting %v", err)
		return ""
	}
	nonceSize := gcm.NonceSize()
	if len(strFromB64) < nonceSize {
		log.Error().Msgf("Unsufficent length %v", err)
		return ""
	}
	nonce, strFromB64 := strFromB64[:nonceSize], strFromB64[nonceSize:]
	decryptedString, err := gcm.Open(nil, []byte(nonce), []byte(strFromB64), nil)
	if err != nil {
		log.Error().Msgf("Error occured while decrypthing %v", err)
		return ""
	}
	log.Debug().Msgf(string(decryptedString))
	return string(decryptedString)
}
