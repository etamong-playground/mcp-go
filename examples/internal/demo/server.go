package demo

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	mcphttp "github.com/etamong-playground/mcp-go"
	"github.com/etamong-playground/mcp-go/authn"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func Settings() (mcphttp.Config, string, error) {
	resource, issuer, client := os.Getenv("MCP_RESOURCE"), os.Getenv("MCP_ISSUER"), os.Getenv("MCP_CLIENT_ID")
	if resource == "" || issuer == "" || client == "" {
		return mcphttp.Config{}, "", errors.New("set MCP_RESOURCE, MCP_ISSUER and MCP_CLIENT_ID")
	}
	return mcphttp.Config{Resource: resource, AuthorizationServers: []string{issuer}, RequiredScopes: []string{"read"}, MaxRequestBytes: 1 << 20, MaxConcurrentRequests: 4, ReadTimeout: 30 * time.Second}, client, nil
}

func Serve(cfg mcphttp.Config, verifier authn.Verifier) error {
	server := mcp.NewServer(&mcp.Implementation{Name: "protected-example", Version: "0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "whoami", Description: "Inspect the authenticated subject", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]string, error) {
		p, ok := mcphttp.PrincipalFromContext(ctx)
		if !ok {
			return nil, nil, authn.ErrInvalidToken
		}
		return nil, map[string]string{"subject": p.Subject}, nil
	})
	endpoint, err := mcphttp.NewProtectedEndpoint(server, verifier, cfg)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", endpoint.Handler())
	mux.Handle("/.well-known/oauth-protected-resource", endpoint.MetadataHandler())
	httpServer := &http.Server{Addr: "127.0.0.1:8080", Handler: endpoint.ReadDeadlineGuard(mux), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute}
	return httpServer.ListenAndServe()
}
