package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type JWTConfig struct {
	Issuer            string
	Resource          string
	ClientIDs         []string
	SigningAlgorithms []string
	HTTPClient        *http.Client
}

type AccessClaims struct {
	ClientID   string
	Scopes     []string
	Attributes map[string]string
}

// AccessTokenProfile must distinguish access tokens from ID tokens and extract the provider's client and scope claims.
type AccessTokenProfile func(json.RawMessage) (AccessClaims, error)

type JWTVerifier struct {
	verifier *oidc.IDTokenVerifier
	resource string
	clients  []string
	profile  AccessTokenProfile
}

func HTTPSURL(raw string, originOnly bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.ForceQuery || strings.Contains(raw, "#") {
		return false
	}
	if originOnly {
		if u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Host, ":") || !canonicalHost(u.Hostname()) {
			return false
		}
		if port := u.Port(); port != "" {
			number, err := strconv.Atoi(port)
			if err != nil || number < 1 || number > 65535 || number == 443 || strconv.Itoa(number) != port {
				return false
			}
		}
	}
	return u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && (!originOnly || u.Path == "")
}

func NewJWTVerifier(ctx context.Context, cfg JWTConfig, profile AccessTokenProfile) (*JWTVerifier, error) {
	if !HTTPSURL(cfg.Issuer, false) || !HTTPSURL(cfg.Resource, true) || profile == nil || len(cfg.ClientIDs) == 0 {
		return nil, errors.New("trusted issuer, resource, clients and access-token profile are required")
	}
	for _, client := range cfg.ClientIDs {
		if strings.TrimSpace(client) == "" || client != strings.TrimSpace(client) {
			return nil, errors.New("client IDs must be nonempty identifiers")
		}
	}
	algorithms := slices.Clone(cfg.SigningAlgorithms)
	if len(algorithms) == 0 {
		algorithms = []string{"RS256"}
	}
	for _, algorithm := range algorithms {
		if !slices.Contains([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}, algorithm) {
			return nil, errors.New("asymmetric signing algorithms are required")
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	boundedClient := *client
	if boundedClient.Timeout <= 0 {
		boundedClient.Timeout = 15 * time.Second
	}
	transport := boundedClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	boundedClient.Transport = boundedIssuerTransport{transport}
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx = oidc.ClientContext(ctx, &boundedClient)
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, errors.New("issuer discovery failed")
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil || !HTTPSURL(metadata.JWKS, false) {
		return nil, errors.New("HTTPS signing-key metadata is required")
	}
	return &JWTVerifier{verifier: provider.Verifier(&oidc.Config{ClientID: cfg.Resource, SupportedSigningAlgs: algorithms}), resource: cfg.Resource, clients: slices.Clone(cfg.ClientIDs), profile: profile}, nil
}

func (v *JWTVerifier) Verify(ctx context.Context, raw string) (Principal, error) {
	if v == nil || v.verifier == nil || v.profile == nil {
		return Principal{}, ErrInvalidToken
	}
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	var claims struct {
		NotBefore int64 `json:"nbf"`
	}
	var document json.RawMessage
	now := time.Now()
	if token.Claims(&document) != nil || token.Claims(&claims) != nil || token.Subject == "" || token.Expiry.IsZero() || !now.Before(token.Expiry) || claims.NotBefore > now.Unix() || token.IssuedAt.After(now.Add(time.Minute)) {
		return Principal{}, ErrInvalidToken
	}
	access, err := v.profile(document)
	if err != nil || !slices.Contains(v.clients, access.ClientID) {
		return Principal{}, ErrInvalidToken
	}
	for _, scope := range access.Scopes {
		if !ValidScope(scope) {
			return Principal{}, ErrInvalidToken
		}
	}
	return (Principal{Issuer: token.Issuer, Subject: token.Subject, ClientID: access.ClientID, Resource: v.resource, Scopes: access.Scopes, ExpiresAt: token.Expiry, Attributes: access.Attributes}).Clone(), nil
}

func ValidScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, c := range scope {
		if c <= 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

const maxIssuerResponseBytes = 1 << 20

type boundedIssuerTransport struct{ base http.RoundTripper }

func (t boundedIssuerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxIssuerResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxIssuerResponseBytes {
		return nil, errors.New("issuer response exceeds size limit")
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

func canonicalHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == "" && !ip.Is4In6() && ip.String() == host
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	if _, err := strconv.ParseUint(last, 0, 32); err == nil {
		return false
	}
	for _, c := range last {
		if c < '0' || c > '9' {
			return len(host) <= 253
		}
	}
	return false
}
