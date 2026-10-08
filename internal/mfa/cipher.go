package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

const KeySize = 32

var ErrDecrypt = errors.New("não foi possível decifrar o segredo de mfa")

type Cipher struct {
	aead cipher.AEAD
}

func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("chave de mfa precisa ter %d bytes, recebida com %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

func ParseKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("chave de mfa precisa estar em base64")
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("chave de mfa precisa ter %d bytes, tem %d", KeySize, len(key))
	}
	return key, nil
}

func GenerateKey() []byte {
	k := make([]byte, KeySize)
	_, _ = rand.Read(k)
	return k
}

func (c *Cipher) seal(plain []byte, userID string) []byte {
	nonce := make([]byte, c.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return c.aead.Seal(nonce, nonce, plain, []byte(userID))
}

func (c *Cipher) open(sealed []byte, userID string) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(sealed) < n {
		return nil, ErrDecrypt
	}
	plain, err := c.aead.Open(nil, sealed[:n], sealed[n:], []byte(userID))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}
