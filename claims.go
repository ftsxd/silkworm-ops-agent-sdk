package silkauth

import "time"

// Claims is the payload of an identity credential.
//
// There is deliberately no field for roles or permissions. A verifier that
// receives extra fields ignores them; authorisation is the receiving service's
// own decision, taken from its own data.
type Claims struct {
	// Issuer is the calling platform's id, as registered with the receiver.
	Issuer string `json:"iss"`
	// Subject is the end user's SSO username, or a service account name
	// such as "agent:release-bot" when no user is involved.
	Subject string `json:"sub"`
	// Audience is the receiving service's id.
	Audience string `json:"aud"`
	// IssuedAt and ExpiresAt are Unix seconds.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
	// ID is unique per credential and is what replay protection keys on.
	ID string `json:"jti"`
	// Context is an optional hint about what the user is looking at, for
	// example {"project": "shop", "app": "order-svc", "env": "prod"}. A
	// receiver may use it to narrow or focus work. It must never be used to
	// widen what the user is allowed to do.
	Context map[string]string `json:"ctx,omitempty"`
}

// Expiry returns ExpiresAt as a time.
func (c *Claims) Expiry() time.Time { return time.Unix(c.ExpiresAt, 0) }
