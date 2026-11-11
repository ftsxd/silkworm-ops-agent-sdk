package silkauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// DefaultLeeway is the clock skew tolerated between caller and receiver.
const DefaultLeeway = 30 * time.Second

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// Audience is this service's id. Credentials for anyone else are refused,
	// so a credential meant for one service cannot be replayed at another.
	Audience string
	// Keys resolves platform public keys. Required.
	Keys KeyResolver
	// Replay rejects reused credential ids. Nil means an in-process store,
	// which is correct for a single instance only.
	Replay ReplayStore
	// Leeway is the tolerated clock skew. Zero means DefaultLeeway.
	Leeway time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
	// OnReject, when set, is told about every request Middleware refuses,
	// for an audit log. It must not write to the response.
	OnReject func(r *http.Request, err error, trace Traceparent)
}

// Verifier checks incoming credentials.
type Verifier struct {
	cfg VerifierConfig
}

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("silkauth: Audience is required")
	}
	if cfg.Keys == nil {
		return nil, errors.New("silkauth: Keys is required")
	}
	if cfg.Replay == nil {
		cfg.Replay = NewMemoryReplayStore()
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = DefaultLeeway
	}
	if cfg.Leeway < 0 || cfg.Leeway > time.Minute {
		return nil, errors.New("silkauth: Leeway must be between 0 and 1m")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg}, nil
}

// Verify checks token and returns its claims. The order matters: the
// signature is checked before any claim is trusted, and the replay record is
// written last, so a credential rejected for any other reason does not use up
// its id.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	p, err := parseCompact(token)
	if err != nil {
		return nil, err
	}
	if p.header.Alg != algEdDSA && p.header.Alg != algRS256 {
		return nil, ErrAlgorithm
	}

	// The issuer is needed to pick the key, so it is read before the
	// signature is verified — and used for nothing else until it is.
	var unverified struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(p.payload, &unverified); err != nil || unverified.Issuer == "" {
		return nil, ErrMalformed
	}
	key, err := v.cfg.Keys.Resolve(ctx, unverified.Issuer, p.header.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifySig(p, key); err != nil {
		return nil, err
	}

	var c Claims
	if err := json.Unmarshal(p.payload, &c); err != nil {
		return nil, ErrMalformed
	}
	if c.Subject == "" || c.ID == "" || c.IssuedAt == 0 || c.ExpiresAt == 0 {
		return nil, ErrMissingClaim
	}
	if c.Audience != v.cfg.Audience {
		return nil, ErrAudience
	}

	now := v.cfg.Now()
	leeway := int64(v.cfg.Leeway / time.Second)
	if c.ExpiresAt+leeway < now.Unix() {
		return nil, ErrExpired
	}
	if c.IssuedAt-leeway > now.Unix() {
		return nil, ErrNotYetValid
	}
	if c.ExpiresAt-c.IssuedAt > int64(MaxLifetime/time.Second) || c.ExpiresAt < c.IssuedAt {
		return nil, ErrLifetime
	}

	first, err := v.cfg.Replay.Use(ctx, c.Issuer, c.ID, time.Unix(c.ExpiresAt+leeway, 0))
	if err != nil {
		return nil, err
	}
	if !first {
		return nil, ErrReplay
	}
	return &c, nil
}
