package authn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	AMRPassword = "pwd"
	AMROTP      = "otp"
	AMRMFA      = "mfa"
)

const (
	algEdDSA     = "EdDSA"
	typJWT       = "JWT"
	maxTokenSize = 8 << 10
)

var (
	ErrMalformed     = errors.New("authn: token malformado")
	ErrSignature     = errors.New("authn: assinatura inválida")
	ErrUnknownKey    = errors.New("authn: chave desconhecida")
	ErrExpired       = errors.New("authn: token expirado")
	ErrNotYetValid   = errors.New("authn: token ainda não é válido")
	ErrWrongIssuer   = errors.New("authn: emissor inesperado")
	ErrWrongAudience = errors.New("authn: audiência inesperada")
)

type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *Audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a Audience) Contains(aud string) bool {
	for _, v := range a {
		if v == aud {
			return true
		}
	}
	return false
}

type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	ID        string   `json:"jti"`
	ClientID  string   `json:"client_id,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	AMR       []string `json:"amr,omitempty"`
}

func (c Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

func (c Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes() {
		if s == scope {
			return true
		}
	}
	return false
}

func (c Claims) HasAMR(method string) bool {
	for _, m := range c.AMR {
		if m == method {
			return true
		}
	}
	return false
}

func (c Claims) IsService() bool {
	return c.ClientID != "" && c.Subject == c.ClientID
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func Sign(key ed25519.PrivateKey, kid string, c Claims) (string, error) {
	h, err := json.Marshal(header{Alg: algEdDSA, Typ: typJWT, Kid: kid})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig), nil
}

type KeySource interface {
	Key(ctx context.Context, kid string) (ed25519.PublicKey, error)
}

type Verifier struct {
	Keys     KeySource
	Issuer   string
	Audience string
	Leeway   time.Duration
	Now      func() time.Time
}

func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	if len(token) > maxTokenSize {
		return Claims{}, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}

	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return Claims{}, ErrMalformed
	}
	if h.Alg != algEdDSA || h.Typ != typJWT || h.Kid == "" {
		return Claims{}, ErrMalformed
	}

	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Claims{}, ErrMalformed
	}

	pub, err := v.Keys.Key(ctx, h.Kid)
	if err != nil {
		return Claims{}, err
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, ErrSignature
	}

	var c Claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return Claims{}, ErrMalformed
	}
	if err := v.validate(c); err != nil {
		return Claims{}, err
	}
	return c, nil
}

func (v *Verifier) validate(c Claims) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if c.Subject == "" || c.ExpiresAt == 0 {
		return ErrMalformed
	}
	if c.Issuer != v.Issuer {
		return ErrWrongIssuer
	}
	if !c.Audience.Contains(v.Audience) {
		return ErrWrongAudience
	}
	if now.After(time.Unix(c.ExpiresAt, 0).Add(v.Leeway)) {
		return ErrExpired
	}
	if c.NotBefore != 0 && now.Add(v.Leeway).Before(time.Unix(c.NotBefore, 0)) {
		return ErrNotYetValid
	}
	return nil
}

func decodeSegment(seg string, dst any) error {
	raw, err := b64.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decodificando segmento: %w", err)
	}
	return nil
}

type StaticKeys map[string]ed25519.PublicKey

func (s StaticKeys) Key(_ context.Context, kid string) (ed25519.PublicKey, error) {
	k, ok := s[kid]
	if !ok {
		return nil, ErrUnknownKey
	}
	return k, nil
}
