package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"log"

	"github.com/shinosaki/webpush-client-go/rfc8291"
)

var (
	CURVE = ecdh.P256()
	HASH  = sha256.New

	PLAINTEXT = "Plain text message!!!"
)

func appserver(authSecret []byte, useragentPublicKey *ecdh.PublicKey) []byte {
	_, salt, privateKey := rfc8291.NewSecrets(CURVE)
	ece := rfc8291.NewRFC8291(HASH)

	encrypted, err := ece.Encrypt(
		[]byte(PLAINTEXT),
		salt,
		authSecret,
		useragentPublicKey,
		privateKey,
	)
	if err != nil {
		log.Panicln("Encryption Error:", err)
	}

	return encrypted
}

func main() {
	// UserAgent
	authSecret, _, useragentPrivateKey := rfc8291.NewSecrets(CURVE)
	ece := rfc8291.NewRFC8291(HASH)

	// AppServer
	encrypted := appserver(authSecret, useragentPrivateKey.PublicKey())

	// UserAgent
	payload, err := rfc8291.Unmarshal(encrypted)
	if err != nil {
		log.Panicln("RFC8291 Unmarshal Error:", err)
	}

	// In RFC8291, KeyID is the AppServer's Public Key
	appserverPublicKey, err := ecdh.P256().NewPublicKey(payload.KeyId)
	if err != nil {
		log.Panicln("Load PublicKey Error", err)
	}

	plaintext, err := ece.Decrypt(
		payload.CipherText,
		payload.Salt,
		authSecret,
		useragentPrivateKey,
		appserverPublicKey,
	)
	if err != nil {
		log.Panicln("RFC8291 Decrypt Error", err)
	}

	log.Println("Valid Message: ", PLAINTEXT)
	log.Println("Decrypted Text:", string(plaintext))
}
