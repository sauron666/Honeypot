package vault

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
)

// ed25519 keys are stored as PKCS#8, the standard the Go x509 package reads and
// writes, so the material interoperates with openssl and anything else that
// speaks PKCS#8 rather than being a MIRAGE-only format.

func marshalPrivate(priv ed25519.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}

func parsePrivate(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("vault: parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("vault: key is not ed25519 (got %T)", key)
	}
	return priv, nil
}
