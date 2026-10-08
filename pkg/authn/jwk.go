package authn

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var b64 = base64.RawURLEncoding

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewJWK(pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   b64.EncodeToString(pub),
		Kid: Thumbprint(pub),
		Use: "sig",
		Alg: "EdDSA",
	}
}

func (k JWK) PublicKey() (ed25519.PublicKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return nil, errors.New("authn: jwk não é Ed25519")
	}
	if k.Alg != "" && k.Alg != "EdDSA" {
		return nil, errors.New("authn: jwk com alg inesperado")
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, errors.New("authn: jwk não é de assinatura")
	}
	raw, err := b64.DecodeString(k.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("authn: jwk com chave inválida")
	}
	return ed25519.PublicKey(raw), nil
}

func Thumbprint(pub ed25519.PublicKey) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + b64.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}
