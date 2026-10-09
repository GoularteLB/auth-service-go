package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GoularteLB/auth-service/pkg/authn"
)

type Options struct {
	Issuer   string
	Audience string
	TTL      time.Duration
}

type Issuer struct {
	key  ed25519.PrivateKey
	kid  string
	opts Options
	jwks authn.JWKS
	now  func() time.Time
}

func NewIssuer(key ed25519.PrivateKey, previous []ed25519.PublicKey, opts Options) *Issuer {
	pub, _ := key.Public().(ed25519.PublicKey)
	jwks := authn.JWKS{Keys: []authn.JWK{authn.NewJWK(pub)}}
	seen := map[string]bool{authn.Thumbprint(pub): true}
	for _, p := range previous {
		jwk := authn.NewJWK(p)
		if seen[jwk.Kid] {
			continue
		}
		seen[jwk.Kid] = true
		jwks.Keys = append(jwks.Keys, jwk)
	}
	return &Issuer{key: key, kid: authn.Thumbprint(pub), opts: opts, jwks: jwks, now: time.Now}
}

func (i *Issuer) Issue(subject, clientID, audience string, scopes, amr []string) (string, time.Duration, error) {
	if audience == "" {
		audience = i.opts.Audience
	}
	now := i.now().UTC()
	token, err := authn.Sign(i.key, i.kid, authn.Claims{
		Issuer:    i.opts.Issuer,
		Subject:   subject,
		Audience:  authn.Audience{audience},
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(i.opts.TTL).Unix(),
		ID:        rand.Text(),
		ClientID:  clientID,
		Scope:     strings.Join(scopes, " "),
		AMR:       amr,
	})
	if err != nil {
		return "", 0, fmt.Errorf("assinando token: %w", err)
	}
	return token, i.opts.TTL, nil
}

func (i *Issuer) JWKS() authn.JWKS {
	return i.jwks
}

func (i *Issuer) KeyID() string {
	return i.kid
}

func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gerando chave: %w", err)
	}
	return priv, nil
}

func EncodePrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("serializando chave: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("esperava um bloco PEM PRIVATE KEY")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("lendo pkcs8: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("a chave não é Ed25519")
	}
	return key, nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("lendo chave: %w", err)
	}
	key, err := ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("chave em %s: %w", path, err)
	}
	return key, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("lendo chave: %w", err)
	}
	key, err := ParsePublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("chave em %s: %w", path, err)
	}
	return key, nil
}

func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("esperava um bloco PEM")
	}
	switch block.Type {
	case "PRIVATE KEY":
		priv, err := ParsePrivateKey(data)
		if err != nil {
			return nil, err
		}
		pub, _ := priv.Public().(ed25519.PublicKey)
		return pub, nil
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("lendo pkix: %w", err)
		}
		pub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("a chave não é Ed25519")
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("bloco PEM %q não suportado", block.Type)
	}
}

func EncodePublicKey(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("serializando chave pública: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
