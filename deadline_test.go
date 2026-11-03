package mcphttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/etamong-playground/mcp-go/authn"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPrincipalDeadlineRejectsMissingOrExpiredAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		for _, ctx := range []context.Context{
			context.Background(),
			context.WithValue(context.Background(), principalKey{}, authn.Principal{}),
			context.WithValue(context.Background(), principalKey{}, authn.Principal{ExpiresAt: now.Add(-time.Second)}),
			context.WithValue(context.Background(), principalKey{}, authn.Principal{ExpiresAt: now}),
		} {
			called := false
			handler := PrincipalDeadline(func(context.Context, string, mcp.Request) (mcp.Result, error) {
				called = true
				return nil, nil
			})
			if _, err := handler(ctx, "tools/call", nil); !errors.Is(err, authn.ErrInvalidToken) || called {
				t.Fatalf("invalid authority dispatched: called=%v err=%v", called, err)
			}
		}
	})
}

func TestPrincipalDeadlinePreservesEarlierDeadlineAndDispatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		expiry := time.Now().Add(time.Hour)
		for _, earlier := range []bool{false, true} {
			parent := context.WithValue(context.Background(), principalKey{}, authn.Principal{ExpiresAt: expiry})
			wantDeadline := expiry
			if earlier {
				wantDeadline = time.Now().Add(time.Minute)
				var cancel context.CancelFunc
				parent, cancel = context.WithDeadline(parent, wantDeadline)
				defer cancel()
			}
			wantResult := &mcp.CallToolResult{IsError: true}
			wantError := errors.New("controlled downstream error")
			var dispatched context.Context
			handler := PrincipalDeadline(func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
				dispatched = ctx
				if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(wantDeadline) {
					t.Fatalf("method deadline = %v, present=%v; want %v", deadline, ok, wantDeadline)
				}
				if method != "tools/call" || request != nil {
					t.Fatal("dispatch arguments changed")
				}
				if _, ok := PrincipalFromContext(ctx); !ok {
					t.Fatal("principal lost")
				}
				return wantResult, wantError
			})
			result, err := handler(parent, "tools/call", nil)
			if result != wantResult || err != wantError {
				t.Fatal("downstream result or error replaced")
			}
			if !errors.Is(dispatched.Err(), context.Canceled) || parent.Err() != nil {
				t.Fatal("derived context was not released independently")
			}
		}
	})
}

func TestPrincipalDeadlineCancelsAtExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		expiry := time.Now().Add(time.Minute)
		ctx := context.WithValue(context.Background(), principalKey{}, authn.Principal{ExpiresAt: expiry})
		handler := PrincipalDeadline(func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
			<-ctx.Done()
			if !time.Now().Equal(expiry) {
				t.Fatal("cancellation did not occur at authority expiry")
			}
			return nil, ctx.Err()
		})
		if _, err := handler(ctx, "tools/call", nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expiry error = %v", err)
		}
	})
}

func TestPrincipalDeadlinePreservesCallerCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent := context.WithValue(context.Background(), principalKey{}, authn.Principal{ExpiresAt: time.Now().Add(time.Hour)})
		ctx, cancel := context.WithCancel(parent)
		handler := PrincipalDeadline(func(ctx context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		})
		if _, err := handler(ctx, "tools/call", nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("caller cancellation lost: %v", err)
		}
		called := false
		handler = PrincipalDeadline(func(context.Context, string, mcp.Request) (mcp.Result, error) {
			called = true
			return nil, nil
		})
		if _, err := handler(ctx, "tools/call", nil); !errors.Is(err, context.Canceled) || called {
			t.Fatal("cancelled caller dispatched")
		}
	})
}

func TestPrincipalDeadlineReachesProtectedSDKTool(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	sdk := server()
	sdk.AddReceivingMiddleware(PrincipalDeadline)
	mcp.AddTool(sdk, &mcp.Tool{Name: "deadline"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]bool, error) {
		deadline, ok := ctx.Deadline()
		return nil, map[string]bool{"bounded": ok && deadline.Equal(expiry)}, nil
	})
	v := authn.VerifierFunc(func(context.Context, string) (authn.Principal, error) {
		p := principal()
		p.ExpiresAt = expiry
		return p, nil
	})
	cfg := config()
	cfg.ReadTimeout = time.Second
	endpoint, err := NewProtectedEndpoint(sdk, v, cfg)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewServer(endpoint.Handler())
	defer host.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "deadline-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: host.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{"fixture"}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "deadline", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("protected call failed: %v", err)
	}
	data, ok := result.StructuredContent.(map[string]any)
	if !ok || data["bounded"] != true {
		t.Fatalf("SDK tool received no authority deadline: %v", result.StructuredContent)
	}
}
