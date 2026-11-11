package silkauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// minRSABits is the smallest RSA key accepted for signing or verification.
const minRSABits = 2048

// GenerateEd25519 returns a new Ed25519 key pair. Ed25519 is the recommended
// key type: small keys, fast signatures, no parameters to get wrong.
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// MarshalPrivateKeyPEM encodes an Ed25519 or RSA private key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	if err := checkKeyType(key.Public()); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKeyPEM encodes an Ed25519 or RSA public key as PKIX PEM. This
// is the file a platform hands to the service it will call.
func MarshalPublicKeyPEM(key crypto.PublicKey) ([]byte, error) {
	if err := checkKeyType(key); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM decodes a PKCS#8 PEM private key (Ed25519 or RSA).
// PKCS#1 "RSA PRIVATE KEY" blocks are accepted too, since that is what many
// existing tools write.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("silkauth: no PEM block found")
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("silkauth: unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("silkauth: key cannot sign")
	}
	if err := checkKeyType(signer.Public()); err != nil {
		return nil, err
	}
	return signer, nil
}

// ParsePublicKeyPEM decodes a PKIX PEM public key (Ed25519 or RSA).
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("silkauth: no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("silkauth: unsupported PEM block %q", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := checkKeyType(key); err != nil {
		return nil, err
	}
	return key, nil
}

// algFor returns the only algorithm a key of this type may be used with.
// Binding the algorithm to the key, instead of trusting the token header, is
// what closes the classic algorithm-confusion attacks.
func algFor(key crypto.PublicKey) (string, error) {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return algEdDSA, nil
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return "", fmt.Errorf("silkauth: RSA key too small (%d bits, need %d)", k.N.BitLen(), minRSABits)
		}
		return algRS256, nil
	default:
		return "", fmt.Errorf("silkauth: unsupported key type %T", key)
	}
}

func checkKeyType(key crypto.PublicKey) error {
	_, err := algFor(key)
	return err
}
