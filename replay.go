package silkauth

import (
	"context"
	"sync"
	"time"
)

// ReplayStore remembers credential ids until they expire.
//
// Use reports whether (issuer, jti) is being used for the first time and, if
// so, records it until exp. It must be atomic: two concurrent calls with the
// same id must not both return true. A multi-instance service needs a shared
// implementation (a database table with a unique key, or Redis SET NX with an
// expiry); MemoryReplayStore only protects a single process.
type ReplayStore interface {
	Use(ctx context.Context, issuer, jti string, exp time.Time) (first bool, err error)
}

// MemoryReplayStore is an in-process ReplayStore.
type MemoryReplayStore struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	now    func() time.Time
	sweeps int
}

// NewMemoryReplayStore returns an empty store.
func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{seen: make(map[string]time.Time), now: time.Now}
}

// Use implements ReplayStore.
func (m *MemoryReplayStore) Use(_ context.Context, issuer, jti string, exp time.Time) (bool, error) {
	key := issuer + "\x00" + jti
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	// Sweep expired entries now and then, so the map is bounded by the
	// request rate times the credential lifetime.
	m.sweeps++
	if m.sweeps >= 1024 {
		m.sweeps = 0
		for k, e := range m.seen {
			if now.After(e) {
				delete(m.seen, k)
			}
		}
	}
	if e, ok := m.seen[key]; ok && !now.After(e) {
		return false, nil
	}
	m.seen[key] = exp
	return true, nil
}
