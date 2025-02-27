package rfc8291

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"log"

	"golang.org/x/crypto/hkdf"
)

const (
	AUTH_SECRET_LEN = 16
	SALT_LEN        = 16

	AES_GCM_OVERHEAD = 16

	HKDF_IKM_LEN   = 32
	HKDF_CEK_LEN   = 16
	HKDF_NONCE_LEN = 12
)

type RFC8291 struct {
	hash func() hash.Hash
}

// Default Hash is SHA256
func NewRFC8291(hash func() hash.Hash) *RFC8291 {
	if hash == nil {
		hash = sha256.New
	}
	return &RFC8291{hash: hash}
}

func NewSecrets(curve ecdh.Curve) (auth, salt []byte, key *ecdh.PrivateKey) {
	auth = make([]byte, AUTH_SECRET_LEN)
	salt = make([]byte, SALT_LEN)
	for _, b := range [][]byte{auth, salt} {
		_, err := io.ReadFull(rand.Reader, b)
		if err != nil {
			log.Panicln("failed to generate random secret", err)
		}
	}

	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Panicln("failed to generate ecdh key", err)
	}

	return auth, salt, key
}

func (c *RFC8291) Encrypt(
	plaintext []byte,
	salt []byte,
	authSecret []byte,
	useragentPublicKey *ecdh.PublicKey,
	appserverPrivateKey *ecdh.PrivateKey,
) ([]byte, error) {
	if len(authSecret) != AUTH_SECRET_LEN {
		return nil, fmt.Errorf("auth_secret must be %d bytes", AUTH_SECRET_LEN)
	}
	if len(salt) != SALT_LEN {
		return nil, fmt.Errorf("salt must be %d bytes", SALT_LEN)
	}

	ecdhSecret, err := appserverPrivateKey.ECDH(useragentPublicKey)
	if err != nil {
		return nil, fmt.Errorf("calculate ecdh_secret failed: %v", err)
	}

	ikm, err := c.ikm(authSecret, ecdhSecret, useragentPublicKey, appserverPrivateKey.PublicKey())
	if err != nil {
		return nil, err
	}

	cek, nonce, err := c.cekAndNonce(ikm, salt)
	if err != nil {
		return nil, err
	}

	gcm, err := c.gcm(cek)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	rs := uint32(len(plaintext) + 1 + AES_GCM_OVERHEAD)

	// RFC8188: 0x01 or 0x02 in tail of plaintext data
	// RFC8291: The push message plaintext has the padding delimiter octet (0x02) appended to produce
	// ciphertext = bytes.Join([][]byte{ciphertext, {0x02}}, []byte{})

	return Marshal(Payload{
		RS:         rs,
		Salt:       salt,
		KeyId:      appserverPrivateKey.PublicKey().Bytes(),
		CipherText: ciphertext,
	}), nil
}

func (c *RFC8291) Decrypt(
	ciphertext []byte,
	salt []byte,
	authSecret []byte,
	useragentPrivateKey *ecdh.PrivateKey,
	appserverPublicKey *ecdh.PublicKey,
) ([]byte, error) {
	if len(authSecret) != AUTH_SECRET_LEN {
		return nil, fmt.Errorf("auth_secret must be %d bytes", AUTH_SECRET_LEN)
	}
	if len(salt) != SALT_LEN {
		return nil, fmt.Errorf("salt must be %d bytes", SALT_LEN)
	}

	ecdhSecret, err := useragentPrivateKey.ECDH(appserverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("calculate ecdh_secret failed: %v", err)
	}

	ikm, err := c.ikm(authSecret, ecdhSecret, useragentPrivateKey.PublicKey(), appserverPublicKey)
	if err != nil {
		return nil, err
	}

	cek, nonce, err := c.cekAndNonce(ikm, salt)
	if err != nil {
		return nil, err
	}

	gcm, err := c.gcm(cek)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// RFC8188: 0x01 or 0x02 in tail of plaintext data
	// RFC8291: The push message plaintext has the padding delimiter octet (0x02) appended to produce
	if plaintext[len(plaintext)-1] == 0x01 || plaintext[len(plaintext)-1] == 0x02 {
		plaintext = plaintext[:len(plaintext)-1]
	}

	return plaintext, err
}

func (c *RFC8291) gcm(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("create cipher block failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM failed: %v", err)
	}

	return gcm, nil
}

func (c *RFC8291) ikm(
	authSecret []byte,
	ecdhSecret []byte,
	useragentPublicKey *ecdh.PublicKey,
	appserverPublicKey *ecdh.PublicKey,
) (ikm []byte, err error) {
	prkKey := hkdf.Extract(c.hash, ecdhSecret, authSecret)

	keyInfo := bytes.Join([][]byte{
		[]byte("WebPush: info\000"),
		useragentPublicKey.Bytes(),
		appserverPublicKey.Bytes(),
	}, []byte{})

	ikm = make([]byte, HKDF_IKM_LEN)
	if _, err := io.ReadFull(hkdf.Expand(c.hash, prkKey, keyInfo), ikm); err != nil {
		return nil, fmt.Errorf("read IKM failed: %v", err)
	}

	return ikm, nil
}

func (c *RFC8291) cekAndNonce(ikm []byte, salt []byte) (cek, nonce []byte, err error) {
	prk := hkdf.Extract(c.hash, ikm, salt)

	cekInfo := []byte("Content-Encoding: aes128gcm\000")
	nonceInfo := []byte("Content-Encoding: nonce\000")

	cek = make([]byte, HKDF_CEK_LEN)
	if _, err := io.ReadFull(hkdf.Expand(c.hash, prk, cekInfo), cek); err != nil {
		return nil, nil, fmt.Errorf("read CEK failed: %v", err)
	}

	nonce = make([]byte, HKDF_NONCE_LEN)
	if _, err := io.ReadFull(hkdf.Expand(c.hash, prk, nonceInfo), nonce); err != nil {
		return nil, nil, fmt.Errorf("read Nonce failed: %v", err)
	}

	return cek, nonce, nil
}
