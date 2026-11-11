package silkauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	algEdDSA = "EdDSA"
	algRS256 = "RS256"

	// maxTokenBytes bounds what the verifier will parse at all.
	maxTokenBytes = 8 << 10
)

var b64 = base64.RawURLEncoding

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ,omitempty"`
}

// signCompact produces a JWS compact serialisation of payload.
func signCompact(key crypto.Signer, kid string, payload any) (string, error) {
	alg, err := algFor(key.Public())
	if err != nil {
		return "", err
	}
	h, err := json.Marshal(header{Alg: alg, Kid: kid, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)

	var sig []byte
	switch alg {
	case algEdDSA:
		sig, err = key.Sign(rand.Reader, []byte(input), crypto.Hash(0))
	case algRS256:
		sum := sha256.Sum256([]byte(input))
		sig, err = key.Sign(rand.Reader, sum[:], crypto.SHA256)
	}
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// parsed is a split, decoded but not yet verified token.
type parsed struct {
	header  header
	payload []byte
	input   string
	sig     []byte
}

func parseCompact(token string) (*parsed, error) {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return nil, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, ErrMalformed
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return nil, ErrMalformed
	}
	return &parsed{header: h, payload: pb, input: parts[0] + "." + parts[1], sig: sig}, nil
}

// verifySig checks the signature with key, requiring the header's algorithm
// to be exactly the one the key type allows.
func verifySig(p *parsed, key crypto.PublicKey) error {
	want, err := algFor(key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknownKey, err)
	}
	if p.header.Alg != want {
		return ErrAlgorithm
	}
	switch k := key.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, []byte(p.input), p.sig) {
			return ErrSignature
		}
	case *rsa.PublicKey:
		sum := sha256.Sum256([]byte(p.input))
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], p.sig) != nil {
			return ErrSignature
		}
	}
	return nil
}
