// Package silkauth signs and verifies the short-lived identity credential a
// platform attaches when it calls another service on behalf of a user.
//
// The credential answers exactly two questions: which platform is calling
// (iss) and which user the call is for (sub, the SSO username). It never
// carries roles or permissions. The receiving service decides those itself, so
// a platform with a bug, or with a leaked key, can at worst speak for a user —
// it can never promote one.
//
// The rules that make this safe are enforced here rather than left to callers:
//
//   - A credential is signed for one request and used once. Signer has no
//     cache, Transport signs inside RoundTrip, and Verifier rejects a jti it
//     has seen before. A long-running job is therefore never affected by the
//     lifetime: the job is authorised when it starts, and every later request
//     about it (poll, resubscribe, reply) carries a fresh credential.
//   - Lifetime is capped at five minutes on both sides.
//   - Only EdDSA (Ed25519) and RS256 are accepted, and the algorithm must match
//     the type of the registered key. "none", HS256 and anything else are
//     refused before any key is touched.
//
// Typical use on a calling platform:
//
//	signer, _ := silkauth.NewSigner(silkauth.SignerConfig{Issuer: "myplatform", KeyID: "myplatform-2026", Key: priv})
//	client := &http.Client{Transport: &silkauth.Transport{Signer: signer, Audience: "silkworm-ops"}}
//	ctx := silkauth.WithSubject(r.Context(), "zhangsan")
//	req, _ := http.NewRequestWithContext(ctx, "POST", url, body)
//	client.Do(req)
//
// Typical use on a receiving service:
//
//	v, _ := silkauth.NewVerifier(silkauth.VerifierConfig{Audience: "silkworm-ops", Keys: keys})
//	http.Handle("/api/v1/", v.Middleware(handler))
//	// inside handler: c, _ := silkauth.ClaimsFromContext(r.Context())
package silkauth
