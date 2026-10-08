package token

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GoularteLB/auth-service/pkg/authn"
)

var opts = Options{Issuer: "auth-service", Audience: "internal", TTL: 5 * time.Minute}

func TestIssueVerifiesAgainstOwnJWKS(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	iss := NewIssuer(key, nil, opts)

	tok, ttl, err := iss.Issue("user-1", "cli_bff", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 5*time.Minute {
		t.Errorf("ttl = %v", ttl)
	}

	keys := authn.StaticKeys{}
	for _, k := range iss.JWKS().Keys {
		pub, err := k.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[k.Kid] = pub
	}
	v := &authn.Verifier{Keys: keys, Issuer: "auth-service", Audience: "internal"}
	c, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user-1" || c.ID == "" || c.ExpiresAt-c.IssuedAt != 300 {
		t.Errorf("claims inesperadas: %+v", c)
	}

	other, _, _ := iss.Issue("user-1", "cli_bff", nil, nil)
	if other == tok {
		t.Error("dois tokens iguais, jti não está variando")
	}
}

func TestJWKSPublishesPreviousKeys(t *testing.T) {
	current, _ := GenerateKey()
	old, _ := GenerateKey()
	oldPub, _ := old.Public().(ed25519.PublicKey)
	curPub, _ := current.Public().(ed25519.PublicKey)

	iss := NewIssuer(current, []ed25519.PublicKey{oldPub, curPub, oldPub}, opts)
	set := iss.JWKS()
	if len(set.Keys) != 2 {
		t.Fatalf("jwks com %d chaves, esperado 2", len(set.Keys))
	}
	if set.Keys[0].Kid != iss.KeyID() {
		t.Error("a chave atual deveria vir primeiro")
	}
	for _, k := range set.Keys {
		if k.X == "" || len(k.X) > 50 {
			t.Errorf("jwk suspeito: %+v", k)
		}
	}
}

func TestPEMRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	data, err := EncodePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jwt.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(loaded) {
		t.Fatal("chave mudou na ida e volta")
	}

	if _, err := ParsePrivateKey([]byte("lixo")); err == nil {
		t.Fatal("aceitou arquivo sem PEM")
	}
}

func TestParsePublicKeyAcceptsBothFormats(t *testing.T) {
	key, _ := GenerateKey()
	want, _ := key.Public().(ed25519.PublicKey)

	privPEM, _ := EncodePrivateKey(key)
	pubPEM, err := EncodePublicKey(want)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"privada": privPEM, "pública": pubPEM} {
		got, err := ParsePublicKey(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !want.Equal(got) {
			t.Fatalf("%s: chave diferente", name)
		}
	}

	if _, err := ParsePublicKey([]byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("aceitou certificado")
	}
}
