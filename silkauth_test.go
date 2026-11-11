package silkauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	signer   *Signer
	verifier *Verifier
	keys     *StaticKeys
	now      *time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_762_693_200, 0)
	clock := func() time.Time { return now }
	s, err := NewSigner(SignerConfig{Issuer: "myplatform", KeyID: "k1", Key: priv, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewStaticKeys(Platform{ID: "myplatform", Keys: map[string]crypto.PublicKey{"k1": pub}})
	if err != nil {
		t.Fatal(err)
	}
	replay := NewMemoryReplayStore()
	replay.now = clock
	v, err := NewVerifier(VerifierConfig{Audience: "silkworm-ops", Keys: keys, Replay: replay, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{signer: s, verifier: v, keys: keys, now: &now}
}

func (f *fixture) advance(d time.Duration) { *f.now = f.now.Add(d) }

func TestSignVerifyRoundTrip(t *testing.T) {
	f := newFixture(t)
	tok, err := f.signer.Sign("zhangsan", "silkworm-ops", WithHint(map[string]string{"app": "order-svc"}))
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.verifier.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "myplatform" || c.Subject != "zhangsan" || c.Audience != "silkworm-ops" {
		t.Fatalf("unexpected claims %+v", c)
	}
	if c.Context["app"] != "order-svc" {
		t.Fatalf("hint lost: %+v", c.Context)
	}
	if c.ExpiresAt-c.IssuedAt != int64(DefaultLifetime/time.Second) {
		t.Fatalf("lifetime %d", c.ExpiresAt-c.IssuedAt)
	}
}

func TestEachSignIsUnique(t *testing.T) {
	f := newFixture(t)
	a, _ := f.signer.Sign("zhangsan", "silkworm-ops")
	b, _ := f.signer.Sign("zhangsan", "silkworm-ops")
	if a == b {
		t.Fatal("two credentials were identical")
	}
}

func TestRejections(t *testing.T) {
	cases := []struct {
		name string
		make func(f *fixture) string
		want error
	}{
		{"wrong audience", func(f *fixture) string {
			tok, _ := f.signer.Sign("zhangsan", "myplatform")
			return tok
		}, ErrAudience},
		{"expired", func(f *fixture) string {
			tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
			f.advance(DefaultLifetime + DefaultLeeway + time.Second)
			return tok
		}, ErrExpired},
		{"issued in the future", func(f *fixture) string {
			f.advance(time.Hour)
			tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
			f.advance(-time.Hour)
			return tok
		}, ErrNotYetValid},
		{"tampered subject", func(f *fixture) string {
			tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
			return replacePayload(t, tok, func(m map[string]any) { m["sub"] = "lisi" })
		}, ErrSignature},
		{"injected roles are not a signature bypass", func(f *fixture) string {
			tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
			return replacePayload(t, tok, func(m map[string]any) { m["roles"] = []string{"ops"} })
		}, ErrSignature},
		{"alg none", func(f *fixture) string {
			tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
			return replaceHeader(t, tok, `{"alg":"none","kid":"k1"}`)
		}, ErrAlgorithm},
		{"alg HS256", func(f *fixture) string {
			tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
			return replaceHeader(t, tok, `{"alg":"HS256","kid":"k1"}`)
		}, ErrAlgorithm},
		{"alg RS256 against an Ed25519 key", func(f *fixture) string {
			tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
			return replaceHeader(t, tok, `{"alg":"RS256","kid":"k1"}`)
		}, ErrAlgorithm},
		{"unknown kid", func(f *fixture) string {
			tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
			return replaceHeader(t, tok, `{"alg":"EdDSA","kid":"nope"}`)
		}, ErrUnknownKey},
		{"garbage", func(f *fixture) string { return "a.b" }, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tok := tc.make(f)
			_, err := f.verifier.Verify(context.Background(), tok)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUnknownAndRevokedIssuer(t *testing.T) {
	f := newFixture(t)
	_, otherPriv, _ := GenerateEd25519()
	other, _ := NewSigner(SignerConfig{Issuer: "evil", KeyID: "k1", Key: otherPriv, Now: func() time.Time { return *f.now }})
	tok, _ := other.Sign("zhangsan", "silkworm-ops")
	if _, err := f.verifier.Verify(context.Background(), tok); !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("unknown issuer: got %v", err)
	}

	pub, priv, _ := GenerateEd25519()
	_ = f.keys.Set(Platform{ID: "myplatform", Keys: map[string]crypto.PublicKey{"k1": pub}, Disabled: true})
	s, _ := NewSigner(SignerConfig{Issuer: "myplatform", KeyID: "k1", Key: priv, Now: func() time.Time { return *f.now }})
	tok, _ = s.Sign("zhangsan", "silkworm-ops")
	if _, err := f.verifier.Verify(context.Background(), tok); !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("revoked issuer: got %v", err)
	}
}

func TestForgedSignatureFromAnotherKey(t *testing.T) {
	f := newFixture(t)
	_, otherPriv, _ := GenerateEd25519()
	forger, _ := NewSigner(SignerConfig{Issuer: "myplatform", KeyID: "k1", Key: otherPriv, Now: func() time.Time { return *f.now }})
	tok, _ := forger.Sign("zhangsan", "silkworm-ops")
	if _, err := f.verifier.Verify(context.Background(), tok); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestReplayRejected(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
	if _, err := f.verifier.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.Verify(context.Background(), tok); !errors.Is(err, ErrReplay) {
		t.Fatalf("second use: got %v", err)
	}
}

func TestReplayConcurrent(t *testing.T) {
	f := newFixture(t)
	tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.verifier.Verify(context.Background(), tok); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d concurrent uses accepted, want 1", ok.Load())
	}
}

func TestRejectedCredentialDoesNotBurnID(t *testing.T) {
	// A credential refused for audience must not be recorded, or a mistaken
	// call would poison the id for nothing. Checked indirectly: the replay
	// store stays empty.
	f := newFixture(t)
	tok, _ := f.signer.Sign("zhangsan", "other")
	_, _ = f.verifier.Verify(context.Background(), tok)
	if n := len(f.verifier.cfg.Replay.(*MemoryReplayStore).seen); n != 0 {
		t.Fatalf("replay store has %d entries", n)
	}
}

func TestLifetimeLimits(t *testing.T) {
	_, priv, _ := GenerateEd25519()
	if _, err := NewSigner(SignerConfig{Issuer: "x", KeyID: "k", Key: priv, TTL: 10 * time.Minute}); err == nil {
		t.Fatal("signer accepted a 10m TTL")
	}
	// A hand-made long-lived token must be refused by the verifier too.
	f := newFixture(t)
	tok, _ := f.signer.Sign("zhangsan", "silkworm-ops")
	long := replacePayload(t, tok, func(m map[string]any) {
		m["exp"] = m["iat"].(float64) + 3600
	})
	// replacePayload breaks the signature, so re-sign by hand.
	long = resign(t, f, long)
	if _, err := f.verifier.Verify(context.Background(), long); !errors.Is(err, ErrLifetime) {
		t.Fatalf("got %v", err)
	}
}

func TestRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s, err := NewSigner(SignerConfig{Issuer: "java-platform", KeyID: "r1", Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := NewStaticKeys(Platform{ID: "java-platform", Keys: map[string]crypto.PublicKey{"r1": &priv.PublicKey}})
	v, _ := NewVerifier(VerifierConfig{Audience: "silkworm-ops", Keys: keys, Now: func() time.Time { return now }})
	tok, _ := s.Sign("zhangsan", "silkworm-ops")
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := NewSigner(SignerConfig{Issuer: "x", KeyID: "k", Key: small}); err == nil {
		t.Fatal("accepted a 1024-bit RSA key")
	}
}

func TestPEMRoundTrip(t *testing.T) {
	pub, priv, _ := GenerateEd25519()
	privPEM, err := MarshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := MarshalPublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	gotPriv, err := ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewSigner(SignerConfig{Issuer: "myplatform", KeyID: "k1", Key: gotPriv})
	keys, _ := NewStaticKeys(Platform{ID: "myplatform", Keys: map[string]crypto.PublicKey{"k1": gotPub}})
	v, _ := NewVerifier(VerifierConfig{Audience: "silkworm-ops", Keys: keys})
	tok, _ := s.Sign("zhangsan", "silkworm-ops")
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
}

// End to end: Transport on the platform side, Middleware on the receiver.
func TestTransportAndMiddleware(t *testing.T) {
	pub, priv, _ := GenerateEd25519()
	signer, _ := NewSigner(SignerConfig{Issuer: "myplatform", KeyID: "k1", Key: priv})
	keys, _ := NewStaticKeys(Platform{
		ID:           "myplatform",
		Keys:         map[string]crypto.PublicKey{"k1": pub},
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})
	verifier, _ := NewVerifier(VerifierConfig{Audience: "silkworm-ops", Keys: keys})

	var mu sync.Mutex
	var subjects, jtis, traces []string
	srv := httptest.NewServer(verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Error("no claims in context")
		}
		tr, _ := TraceFrom(r.Context())
		mu.Lock()
		subjects = append(subjects, c.Subject)
		jtis = append(jtis, c.ID)
		traces = append(traces, tr.TraceID)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})))
	defer srv.Close()

	client := &http.Client{Transport: &Transport{Signer: signer, Audience: "silkworm-ops"}}
	trace := NewTraceparent()
	ctx := WithTrace(WithSubject(context.Background(), "zhangsan"), trace)

	// Start, then poll three times: every request must carry its own credential.
	for i := 0; i < 4; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/agent/runs/r1", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
		if got, _ := ParseTraceparent(resp.Header.Get(HeaderTraceparent)); got.TraceID != trace.TraceID {
			t.Fatalf("response trace %q, want trace id %s", resp.Header.Get(HeaderTraceparent), trace.TraceID)
		}
	}
	seen := map[string]bool{}
	for i := range jtis {
		if subjects[i] != "zhangsan" {
			t.Fatalf("subject %q", subjects[i])
		}
		if traces[i] != trace.TraceID {
			t.Fatalf("trace not propagated: %q", traces[i])
		}
		if seen[jtis[i]] {
			t.Fatal("a credential was reused across requests")
		}
		seen[jtis[i]] = true
	}

	// No subject in context: the transport refuses to send at all.
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := client.Do(req); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("missing subject: got %v", err)
	}

	// No credential: 401, with a trace id to quote when asking why.
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: status %d", resp.StatusCode)
	}
}

func TestMiddlewareRemoteNotAllowed(t *testing.T) {
	pub, priv, _ := GenerateEd25519()
	signer, _ := NewSigner(SignerConfig{Issuer: "myplatform", KeyID: "k1", Key: priv})
	keys, _ := NewStaticKeys(Platform{
		ID:           "myplatform",
		Keys:         map[string]crypto.PublicKey{"k1": pub},
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	verifier, _ := NewVerifier(VerifierConfig{Audience: "silkworm-ops", Keys: keys})
	h := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run")
	}))
	tok, _ := signer.Sign("zhangsan", "silkworm-ops")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.5:5000"
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestTraceparent(t *testing.T) {
	tp := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	got, ok := ParseTraceparent(tp)
	if !ok || got.String() != tp {
		t.Fatalf("parse %q: %+v %v", tp, got, ok)
	}
	for _, bad := range []string{"", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", "00-XYZ-00f067aa0ba902b7-01"} {
		if _, ok := ParseTraceparent(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
	child := got.Child()
	if child.TraceID != got.TraceID || child.SpanID == got.SpanID {
		t.Fatalf("child %+v", child)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderRequestID, "4BF92F35-77B3-4DA6-A3CE-929D0E0E4736")
	if TraceFromRequest(r).TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatal("X-Request-Id fallback")
	}
}

// --- helpers ---

func replacePayload(t *testing.T, tok string, edit func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, _ := json.Marshal(m)
	return parts[0] + "." + b64.EncodeToString(out) + "." + parts[2]
}

func replaceHeader(t *testing.T, tok, hdr string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	return b64.EncodeToString([]byte(hdr)) + "." + parts[1] + "." + parts[2]
}

// resign signs tok's header+payload again with the fixture's key.
func resign(t *testing.T, f *fixture, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	input := parts[0] + "." + parts[1]
	sig, err := f.signer.cfg.Key.Sign(rand.Reader, []byte(input), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}
