package silkauth

import "errors"

// Errors a verifier returns. Callers may branch on them with errors.Is; the
// middleware maps all of them to 401 without revealing which one occurred.
var (
	ErrMalformed      = errors.New("silkauth: malformed credential")
	ErrAlgorithm      = errors.New("silkauth: algorithm not allowed")
	ErrUnknownIssuer  = errors.New("silkauth: unknown or revoked issuer")
	ErrUnknownKey     = errors.New("silkauth: unknown key id")
	ErrSignature      = errors.New("silkauth: invalid signature")
	ErrAudience       = errors.New("silkauth: wrong audience")
	ErrExpired        = errors.New("silkauth: credential expired")
	ErrNotYetValid    = errors.New("silkauth: credential issued in the future")
	ErrLifetime       = errors.New("silkauth: credential lifetime too long")
	ErrMissingClaim   = errors.New("silkauth: required claim missing")
	ErrReplay         = errors.New("silkauth: credential already used")
	ErrRemoteNotAllow = errors.New("silkauth: caller address not allowed")
	ErrNoSubject      = errors.New("silkauth: no subject in context")
)
