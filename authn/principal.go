package authn

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"
)

var ErrInvalidToken = errors.New("invalid access token")

// Principal contains authenticated access-token attributes, not application permissions.
type Principal struct {
	Issuer     string
	Subject    string
	ClientID   string
	Resource   string
	Scopes     []string
	ExpiresAt  time.Time
	Attributes map[string]string
}

// Verifier must verify token authenticity, access-token classification and client/resource binding.
// It must return no principal when verification fails.
type Verifier interface {
	Verify(context.Context, string) (Principal, error)
}

type VerifierFunc func(context.Context, string) (Principal, error)

func (f VerifierFunc) Verify(ctx context.Context, token string) (Principal, error) {
	return f(ctx, token)
}

func (p Principal) Clone() Principal {
	p.Scopes = slices.Clone(p.Scopes)
	p.Attributes = maps.Clone(p.Attributes)
	return p
}
