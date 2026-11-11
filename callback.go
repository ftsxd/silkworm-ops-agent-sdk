package silkauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// A callback is the receiving service calling the platform back with a
// result: silkworm-ops POSTing a finished asynchronous run to the
// callback_url the platform gave. The roles swap. The service signs with
// its own key (iss is the service's id, aud is the platform's id, sub is the
// user the run was for), and the platform verifies.
//
// A credential alone does not cover a body, so a signed callback also carries
// the body's SHA-256 in its ctx. VerifyCallback checks both; Middleware
// cannot, because it does not read bodies.

// Hint keys a signed callback carries.
const (
	HintRunID      = "run_id"
	HintBodySHA256 = "body_sha256"
)

// ErrBodyMismatch: the callback's body is not the one that was signed.
var ErrBodyMismatch = errors.New("silkauth: callback body does not match its signature")

// CallbackHint is what a sender signs into a callback's credential, with
// WithHint, so the receiver can check the body: the run it is about and the
// body's SHA-256.
func CallbackHint(runID string, body []byte) map[string]string {
	sum := sha256.Sum256(body)
	return map[string]string{HintRunID: runID, HintBodySHA256: hex.EncodeToString(sum[:])}
}

// DefaultCallbackMaxBytes bounds the body VerifyCallback reads.
const DefaultCallbackMaxBytes = 4 << 20

// VerifyCallback checks a signed callback request and returns its claims and
// body. v must be configured with the platform's own id as Audience and the
// sender's public key (for silkworm-ops: issuer "silkworm-ops" and the key
// shown on its 接入平台 page). maxBytes <= 0 means DefaultCallbackMaxBytes.
//
// The body is read in full, so r.Body is consumed; use the returned bytes.
// The claims' Context carries the run id under HintRunID.
func VerifyCallback(ctx context.Context, v *Verifier, r *http.Request, maxBytes int64) (*Claims, []byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultCallbackMaxBytes
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, nil, ErrMalformed
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("silkauth: read callback body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, nil, fmt.Errorf("silkauth: callback body over %d bytes", maxBytes)
	}
	c, err := v.Verify(ctx, strings.TrimSpace(token))
	if err != nil {
		return nil, nil, err
	}
	want := CallbackHint("", body)[HintBodySHA256]
	got := c.Context[HintBodySHA256]
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return nil, nil, ErrBodyMismatch
	}
	return c, body, nil
}
