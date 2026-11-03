package mcphttp

import (
	"context"
	"time"

	"github.com/etamong-playground/mcp-go/authn"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// PrincipalDeadline requires a protected endpoint principal and bounds SDK method
// contexts by its expiry. Handlers must propagate the context to downstream work;
// cancellation does not forcibly stop a handler that ignores it.
func PrincipalDeadline(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		principal, ok := PrincipalFromContext(ctx)
		if !ok || principal.ExpiresAt.IsZero() || !time.Now().Before(principal.ExpiresAt) {
			return nil, authn.ErrInvalidToken
		}
		bounded, cancel := context.WithDeadline(ctx, principal.ExpiresAt)
		defer cancel()
		return next(bounded, method, request)
	}
}
