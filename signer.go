package silkauth

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxLifetime is the longest a credential may live. Signers refuse to issue
// longer ones and verifiers refuse to accept them.
const MaxLifetime = 5 * time.Minute

// DefaultLifetime is used when SignerConfig.TTL is zero. It is shorter than
// the maximum so that ordinary clock drift between machines does not push a
// fresh credential over the verifier's limit.
const DefaultLifetime = 2 * time.Minute

// SignerConfig configures a Signer.
type SignerConfig struct {
	// Issuer is this platform's id, as registered with the services it calls.
	Issuer string
	// KeyID names the key pair, so a receiver can hold the old and new public
	// key side by side while a platform rotates.
	KeyID string
	// Key is the platform's private key (Ed25519 recommended, or RSA ≥ 2048).
	Key crypto.Signer
	// TTL is how long each credential is valid. Zero means DefaultLifetime;
	// anything above MaxLifetime is an error.
	TTL time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Signer issues one credential per call. It holds no cache on purpose: a
// credential is single-use, so reusing one would fail replay protection.
type Signer struct {
	cfg SignerConfig
}

// NewSigner validates cfg and returns a Signer.
func NewSigner(cfg SignerConfig) (*Signer, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("silkauth: Issuer is required")
	}
	if strings.TrimSpace(cfg.KeyID) == "" {
		return nil, errors.New("silkauth: KeyID is required")
	}
	if cfg.Key == nil {
		return nil, errors.New("silkauth: Key is required")
	}
	if err := checkKeyType(cfg.Key.Public()); err != nil {
		return nil, err
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultLifetime
	}
	if cfg.TTL < 0 || cfg.TTL > MaxLifetime {
		return nil, fmt.Errorf("silkauth: TTL must be between 1s and %s", MaxLifetime)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Signer{cfg: cfg}, nil
}

// Issuer returns the issuer this signer writes into every credential.
func (s *Signer) Issuer() string { return s.cfg.Issuer }

// SignOption adjusts one credential.
type SignOption func(*Claims)

// WithHint attaches a context hint (see Claims.Context). Hints only ever
// narrow what the receiver does; they grant nothing.
func WithHint(hint map[string]string) SignOption {
	return func(c *Claims) {
		if len(hint) == 0 {
			return
		}
		c.Context = make(map[string]string, len(hint))
		for k, v := range hint {
			c.Context[k] = v
		}
	}
}

// Sign returns a fresh credential saying this platform is calling audience on
// behalf of subject. Call it once per outgoing request.
func (s *Signer) Sign(subject, audience string, opts ...SignOption) (string, error) {
	if strings.TrimSpace(subject) == "" {
		return "", ErrNoSubject
	}
	if strings.TrimSpace(audience) == "" {
		return "", errors.New("silkauth: audience is required")
	}
	jti, err := newID()
	if err != nil {
		return "", err
	}
	now := s.cfg.Now()
	c := &Claims{
		Issuer:    s.cfg.Issuer,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.cfg.TTL).Unix(),
		ID:        jti,
	}
	for _, o := range opts {
		o(c)
	}
	return signCompact(s.cfg.Key, s.cfg.KeyID, c)
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
