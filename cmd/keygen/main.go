package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GoularteLB/auth-service/internal/token"
	"github.com/GoularteLB/auth-service/pkg/authn"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 || !strings.HasSuffix(args[0], ".pem") {
		return errors.New("uso: keygen <arquivo.pem>")
	}
	privPath := filepath.Clean(args[0])
	pubPath := strings.TrimSuffix(privPath, ".pem") + ".pub.pem"

	key, err := token.GenerateKey()
	if err != nil {
		return err
	}
	pub, _ := key.Public().(ed25519.PublicKey)

	privPEM, err := token.EncodePrivateKey(key)
	if err != nil {
		return err
	}
	pubPEM, err := token.EncodePublicKey(pub)
	if err != nil {
		return err
	}

	if err := writeNew(privPath, privPEM); err != nil {
		return err
	}
	if err := writeNew(pubPath, pubPEM); err != nil {
		return err
	}

	fmt.Printf("chave privada em %s\nchave pública em %s\nkid %s\n", privPath, pubPath, authn.Thumbprint(pub))
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
