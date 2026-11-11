package silkauth

import "context"

type ctxKey int

const (
	subjectKey ctxKey = iota
	hintKey
	claimsKey
	traceKey
)

// WithSubject records which user an outgoing request is for. Transport reads
// it when signing. Set it where the platform knows the logged-in user (for
// example right after its own session middleware), or, for a background job,
// from the username stored with the job when it was started.
func WithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectKey, subject)
}

// SubjectFrom returns the subject set by WithSubject.
func SubjectFrom(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(subjectKey).(string)
	return s, ok && s != ""
}

// WithHintContext attaches a context hint to outgoing requests made with ctx.
func WithHintContext(ctx context.Context, hint map[string]string) context.Context {
	return context.WithValue(ctx, hintKey, hint)
}

func hintFrom(ctx context.Context) map[string]string {
	h, _ := ctx.Value(hintKey).(map[string]string)
	return h
}

// ClaimsFromContext returns the verified claims the middleware stored.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*Claims)
	return c, ok
}

// WithClaims stores verified claims. The middleware calls it; it is exported
// for services that verify outside HTTP (for example an A2A or gRPC handler).
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}
