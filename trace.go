package silkauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// Header names used for trace propagation.
const (
	HeaderTraceparent = "traceparent"
	HeaderRequestID   = "X-Request-Id"
)

// Traceparent is a parsed W3C traceparent value.
type Traceparent struct {
	TraceID string // 32 lowercase hex
	SpanID  string // 16 lowercase hex
	Flags   string // 2 hex
}

// String renders the header value.
func (t Traceparent) String() string {
	return "00-" + t.TraceID + "-" + t.SpanID + "-" + t.Flags
}

// ParseTraceparent parses a W3C traceparent header value.
func ParseTraceparent(v string) (Traceparent, bool) {
	parts := strings.Split(strings.TrimSpace(v), "-")
	if len(parts) != 4 || parts[0] != "00" {
		return Traceparent{}, false
	}
	if !isHex(parts[1], 32) || !isHex(parts[2], 16) || !isHex(parts[3], 2) {
		return Traceparent{}, false
	}
	if parts[1] == strings.Repeat("0", 32) || parts[2] == strings.Repeat("0", 16) {
		return Traceparent{}, false
	}
	return Traceparent{TraceID: parts[1], SpanID: parts[2], Flags: parts[3]}, true
}

// NewTraceparent starts a new trace.
func NewTraceparent() Traceparent {
	return Traceparent{TraceID: randHex(16), SpanID: randHex(8), Flags: "01"}
}

// Child keeps the trace id and gives a new span id, for an outgoing call.
func (t Traceparent) Child() Traceparent {
	return Traceparent{TraceID: t.TraceID, SpanID: randHex(8), Flags: t.Flags}
}

// WithTrace stores the trace an outgoing request belongs to.
func WithTrace(ctx context.Context, t Traceparent) context.Context {
	return context.WithValue(ctx, traceKey, t)
}

// TraceFrom returns the trace stored by WithTrace or by the middleware.
func TraceFrom(ctx context.Context) (Traceparent, bool) {
	t, ok := ctx.Value(traceKey).(Traceparent)
	return t, ok
}

// TraceFromRequest reads traceparent, falling back to X-Request-Id when it
// is a 32-hex id, and starts a new trace when neither is usable.
func TraceFromRequest(r *http.Request) Traceparent {
	if t, ok := ParseTraceparent(r.Header.Get(HeaderTraceparent)); ok {
		return t
	}
	if id := strings.ToLower(strings.ReplaceAll(r.Header.Get(HeaderRequestID), "-", "")); isHex(id, 32) {
		return Traceparent{TraceID: id, SpanID: randHex(8), Flags: "01"}
	}
	return NewTraceparent()
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
