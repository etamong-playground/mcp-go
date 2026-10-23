package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log"
	"os"
	"time"

	"github.com/etamong-playground/mcp-go/authn"
	"github.com/etamong-playground/mcp-go/examples/internal/demo"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	cfg, client, err := demo.Settings()
	if err != nil {
		return err
	}
	token := os.Getenv("MCP_BEARER_TOKEN")
	expiry, err := time.Parse(time.RFC3339, os.Getenv("MCP_TOKEN_EXPIRY"))
	if len(token) < 32 || err != nil || !time.Now().Before(expiry) {
		return errors.New("set a random MCP_BEARER_TOKEN of at least32characters and future RFC3339 MCP_TOKEN_EXPIRY")
	}
	expected := sha256.Sum256([]byte(token))
	verifier := authn.VerifierFunc(func(_ context.Context, raw string) (authn.Principal, error) {
		received := sha256.Sum256([]byte(raw))
		if subtle.ConstantTimeCompare(expected[:], received[:]) != 1 || !time.Now().Before(expiry) {
			return authn.Principal{}, authn.ErrInvalidToken
		}
		return authn.Principal{Issuer: cfg.AuthorizationServers[0], Resource: cfg.Resource, ClientID: client, Subject: "provisioned-example-user", Scopes: []string{"read"}, ExpiresAt: expiry}, nil
	})
	return demo.Serve(cfg, verifier)
}
