package authn

import (
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (JWTConfig, func(map[string]any) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "fixture-key", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	issuer = server.URL
	cfg := JWTConfig{Issuer: issuer, Resource: "https://service.example", ClientIDs: []string{"native-fixture"}, HTTPClient: server.Client()}
	sign := func(changes map[string]any) string {
		claims := map[string]any{"iss": issuer, "aud": cfg.Resource, "sub": "user-fixture", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "token_use": "access", "client_id": "native-fixture", "scope": "read write"}
		for key, value := range changes {
			if value == nil {
				delete(claims, key)
			} else {
				claims[key] = value
			}
		}
		raw, _ := json.Marshal(claims)
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture-key"}`))
		signed := header + "." + base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(signed))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	return cfg, sign
}

func fixtureProfile(raw json.RawMessage) (AccessClaims, error) {
	var claims struct {
		Use    string `json:"token_use"`
		Client string `json:"client_id"`
		Scope  string `json:"scope"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Use != "access" {
		return AccessClaims{}, ErrInvalidToken
	}
	return AccessClaims{ClientID: claims.Client, Scopes: strings.Fields(claims.Scope), Attributes: map[string]string{"fixture": "validated"}}, nil
}

func TestJWTAccessTokenContract(t *testing.T) {
	cfg, sign := fixture(t)
	verifier, err := NewJWTVerifier(context.Background(), cfg, fixtureProfile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ClientIDs[0] = "untrusted-client"
	principal, err := verifier.Verify(context.Background(), sign(nil))
	if err != nil || principal.Subject != "user-fixture" || principal.Issuer != cfg.Issuer || principal.Resource != cfg.Resource || principal.ClientID != "native-fixture" || len(principal.Scopes) != 2 || principal.Attributes["fixture"] != "validated" {
		t.Fatalf("access identity mismatch: %+v %v", principal, err)
	}
	for name, changes := range map[string]map[string]any{
		"issuer": {"iss": "https://wrong.example"}, "audience": {"aud": "https://wrong.example"}, "expired": {"exp": time.Now().Add(-time.Minute).Unix()}, "no expiry": {"exp": nil}, "no subject": {"sub": nil}, "no client": {"client_id": nil}, "wrong client": {"client_id": "untrusted-client"}, "ID token": {"token_use": "id"}, "no classification": {"token_use": nil}, "future nbf": {"nbf": time.Now().Add(time.Hour).Unix()}, "future iat": {"iat": time.Now().Add(time.Hour).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), sign(changes)); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("invalid token accepted: %v", err)
			}
		})
	}
	raw := sign(nil)
	parts := strings.Split(raw, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 1
	for _, raw := range []string{"malformed", parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)} {
		if _, err := verifier.Verify(context.Background(), raw); !errors.Is(err, ErrInvalidToken) {
			t.Fatal("malformed/signature credential accepted")
		}
	}
}

func TestJWTConstructionRejectsMissingTrust(t *testing.T) {
	cfg, _ := fixture(t)
	for name, change := range map[string]func(*JWTConfig){
		"HTTP issuer": func(c *JWTConfig) { c.Issuer = "http://issuer.example" }, "resource path": func(c *JWTConfig) { c.Resource += "/path" }, "resource userinfo": func(c *JWTConfig) { c.Resource = "https://user@service.example" }, "no clients": func(c *JWTConfig) { c.ClientIDs = nil }, "empty client": func(c *JWTConfig) { c.ClientIDs = []string{""} }, "weak algorithm": func(c *JWTConfig) { c.SigningAlgorithms = []string{"HS256"} },
	} {
		t.Run(name, func(t *testing.T) {
			copy := cfg
			change(&copy)
			if _, err := NewJWTVerifier(context.Background(), copy, fixtureProfile); err == nil {
				t.Fatal("invalid trust accepted")
			}
		})
	}
	if _, err := NewJWTVerifier(context.Background(), cfg, nil); err == nil {
		t.Fatal("missing access profile accepted")
	}
	var nilVerifier *JWTVerifier
	if _, err := nilVerifier.Verify(context.Background(), "anything"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("uninitialized verifier accepted")
	}
}

func TestJWTDiscoveryCannotFollowRedirect(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true; w.WriteHeader(200) }))
	defer target.Close()
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer issuer.Close()
	_, err := NewJWTVerifier(context.Background(), JWTConfig{Issuer: issuer.URL, Resource: "https://service.example", ClientIDs: []string{"native"}, HTTPClient: issuer.Client()}, fixtureProfile)
	if err == nil || followed {
		t.Fatal("discovery followed an untrusted redirect")
	}
}

func TestIssuerResponsesAreBounded(t *testing.T) {
	fixtureConfig, sign := fixture(t)
	response, err := fixtureConfig.HTTPClient.Get(fixtureConfig.Issuer + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range []string{"discovery", "keys", "discovery gzip", "keys gzip"} {
		t.Run(document, func(t *testing.T) {
			var issuer string
			host := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var output io.Writer = w
				if strings.HasSuffix(document, " gzip") {
					w.Header().Set("Content-Encoding", "gzip")
					compressed := gzip.NewWriter(w)
					defer compressed.Close()
					output = compressed
				}
				if r.URL.Path == "/.well-known/openid-configuration" {
					if strings.HasPrefix(document, "discovery") {
						_, _ = io.WriteString(output, strings.Repeat(" ", (1<<20)+1))
					}
					_ = json.NewEncoder(output).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys"})
				} else {
					_, _ = io.WriteString(output, strings.Repeat(" ", (1<<20)+1))
					_, _ = output.Write(keys)
				}
			}))
			defer host.Close()
			issuer = host.URL
			v, err := NewJWTVerifier(context.Background(), JWTConfig{Issuer: issuer, Resource: "https://service.example", ClientIDs: []string{"native-fixture"}, HTTPClient: host.Client()}, fixtureProfile)
			if strings.HasPrefix(document, "discovery") {
				if err == nil {
					t.Fatal("oversized discovery accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Verify(context.Background(), sign(map[string]any{"iss": issuer})); !errors.Is(err, ErrInvalidToken) {
				t.Fatal("oversized JWKS accepted")
			}
		})
	}
}

func TestResourceOriginMustBeCanonical(t *testing.T) {
	for _, resource := range []string{"https://SERVICE.example", "https://service.example:443", "https://service.example:0443", "https://service.example:08443", "https://service.example:", "https://bücher.example", "https://[0:0:0:0:0:0:0:1]", "https://127.1", "https://0177.0.0.1", "https://service.example?", "https://service.example#"} {
		if HTTPSURL(resource, true) {
			t.Errorf("noncanonical resource accepted: %s", resource)
		}
	}
}
