package silkauth

import (
	"context"
	"crypto"
	"fmt"
	"net/netip"
	"sync"
)

// KeyResolver finds the public key registered for an issuer and key id. It
// returns ErrUnknownIssuer for an issuer that is not registered or has been
// revoked, and ErrUnknownKey for an unknown key id of a known issuer.
type KeyResolver interface {
	Resolve(ctx context.Context, issuer, kid string) (crypto.PublicKey, error)
}

// Platform is one registered caller.
type Platform struct {
	// ID is the value the platform writes into iss.
	ID string
	// Keys maps key id to public key. Holding two lets a platform rotate
	// without downtime: register the new key, switch signing, drop the old.
	Keys map[string]crypto.PublicKey
	// AllowedCIDRs, when non-empty, restricts where the platform may call
	// from. Checked by the middleware against the connection's remote address.
	AllowedCIDRs []netip.Prefix
	// Disabled revokes the platform without deleting its record.
	Disabled bool
}

// StaticKeys is a KeyResolver over an in-memory set of platforms. It is safe
// for concurrent use and can be replaced wholesale with Set, so a service can
// reload its platform registry without restarting.
type StaticKeys struct {
	mu        sync.RWMutex
	platforms map[string]Platform
}

// NewStaticKeys builds a resolver from platforms. Every key is checked to be
// a supported type.
func NewStaticKeys(platforms ...Platform) (*StaticKeys, error) {
	s := &StaticKeys{}
	if err := s.Set(platforms...); err != nil {
		return nil, err
	}
	return s, nil
}

// Set replaces the registered platforms.
func (s *StaticKeys) Set(platforms ...Platform) error {
	m := make(map[string]Platform, len(platforms))
	for _, p := range platforms {
		if p.ID == "" {
			return fmt.Errorf("silkauth: platform with empty ID")
		}
		for kid, k := range p.Keys {
			if err := checkKeyType(k); err != nil {
				return fmt.Errorf("silkauth: platform %s key %s: %w", p.ID, kid, err)
			}
		}
		m[p.ID] = p
	}
	s.mu.Lock()
	s.platforms = m
	s.mu.Unlock()
	return nil
}

// Resolve implements KeyResolver.
func (s *StaticKeys) Resolve(_ context.Context, issuer, kid string) (crypto.PublicKey, error) {
	s.mu.RLock()
	p, ok := s.platforms[issuer]
	s.mu.RUnlock()
	if !ok || p.Disabled {
		return nil, ErrUnknownIssuer
	}
	k, ok := p.Keys[kid]
	if !ok {
		return nil, ErrUnknownKey
	}
	return k, nil
}

// AllowRemote reports whether issuer may call from addr. A platform with no
// CIDRs configured is allowed from anywhere.
func (s *StaticKeys) AllowRemote(issuer string, addr netip.Addr) bool {
	s.mu.RLock()
	p, ok := s.platforms[issuer]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if len(p.AllowedCIDRs) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, c := range p.AllowedCIDRs {
		if c.Contains(addr) {
			return true
		}
	}
	return false
}
