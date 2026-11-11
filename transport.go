package silkauth

import (
	"errors"
	"net/http"
)

// Transport is an http.RoundTripper that signs a fresh credential into every
// request it sends. Wrap the client a platform uses to call one service, and
// business code never handles credentials at all: starting a job, polling it,
// resubscribing and replying each get their own credential automatically.
type Transport struct {
	// Signer issues the credentials. Required.
	Signer *Signer
	// Audience is the id of the service being called, e.g. "silkworm-ops".
	Audience string
	// Subject, when set, decides the user for a request. When nil the subject
	// comes from the request context (WithSubject).
	Subject func(*http.Request) (string, error)
	// Base performs the request. Nil means http.DefaultTransport.
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Signer == nil {
		return nil, errors.New("silkauth: Transport.Signer is nil")
	}
	subject, err := t.subject(req)
	if err != nil {
		return nil, err
	}
	var opts []SignOption
	if hint := hintFrom(req.Context()); len(hint) > 0 {
		opts = append(opts, WithHint(hint))
	}
	token, err := t.Signer.Sign(subject, t.Audience, opts...)
	if err != nil {
		return nil, err
	}

	// RoundTrippers must not modify the caller's request.
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+token)
	if out.Header.Get(HeaderTraceparent) == "" {
		if tr, ok := TraceFrom(req.Context()); ok {
			out.Header.Set(HeaderTraceparent, tr.Child().String())
		}
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(out)
}

func (t *Transport) subject(req *http.Request) (string, error) {
	if t.Subject != nil {
		return t.Subject(req)
	}
	if s, ok := SubjectFrom(req.Context()); ok {
		return s, nil
	}
	return "", ErrNoSubject
}
