package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"

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
	profile := func(raw json.RawMessage) (authn.AccessClaims, error) {
		var claims struct {
			Use    string `json:"token_use"`
			Client string `json:"client_id"`
			Scope  string `json:"scope"`
		}
		if json.Unmarshal(raw, &claims) != nil || claims.Use != "access" {
			return authn.AccessClaims{}, authn.ErrInvalidToken
		}
		return authn.AccessClaims{ClientID: claims.Client, Scopes: strings.Fields(claims.Scope)}, nil
	}
	verifier, err := authn.NewJWTVerifier(context.Background(), authn.JWTConfig{Issuer: cfg.AuthorizationServers[0], Resource: cfg.Resource, ClientIDs: []string{client}}, profile)
	if err != nil {
		return err
	}
	return demo.Serve(cfg, verifier)
}
