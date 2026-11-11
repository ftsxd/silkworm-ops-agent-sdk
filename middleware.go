package silkauth

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// RemoteChecker restricts where an issuer may call from. StaticKeys
// implements it.
type RemoteChecker interface {
	AllowRemote(issuer string, addr netip.Addr) bool
}

// Middleware verifies the Authorization header, stores the claims and the
// trace in the request context, echoes the trace back in the response, and
// answers 401 for anything that fails.
//
// The remote address is taken from the connection, not from X-Forwarded-For:
// behind a reverse proxy, put the proxy's own allow-listing in front, or
// configure CIDRs that match the proxy.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace := TraceFromRequest(r)
		w.Header().Set(HeaderTraceparent, trace.String())

		c, err := v.verifyRequest(r)
		if err != nil {
			slog.Warn("silkauth: rejected request",
				"err", err, "path", r.URL.Path, "remote", r.RemoteAddr, "trace_id", trace.TraceID)
			if v.cfg.OnReject != nil {
				v.cfg.OnReject(r, err, trace)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","trace_id":"` + trace.TraceID + `"}`))
			return
		}
		ctx := WithClaims(r.Context(), c)
		ctx = WithTrace(ctx, trace)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (v *Verifier) verifyRequest(r *http.Request) (*Claims, error) {
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		return nil, ErrMalformed
	}
	c, err := v.Verify(r.Context(), strings.TrimSpace(token))
	if err != nil {
		return nil, err
	}
	if rc, ok := v.cfg.Keys.(RemoteChecker); ok {
		addr, err := remoteAddr(r.RemoteAddr)
		if err != nil || !rc.AllowRemote(c.Issuer, addr) {
			return nil, ErrRemoteNotAllow
		}
	}
	return c, nil
}

func remoteAddr(hostport string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errors.New("silkauth: unparseable remote address")
	}
	return addr, nil
}
