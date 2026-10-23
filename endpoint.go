package mcphttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/etamong-playground/mcp-go/authn"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Config struct {
	Resource              string
	AuthorizationServers  []string
	RequiredScopes        []string
	SupportedScopes       []string
	Path                  string
	MetadataURL           string
	MaxRequestBytes       int64
	MaxConcurrentRequests int
	ReadTimeout           time.Duration
	// WriteError customizes rejected transport responses; it cannot continue dispatch.
	WriteError func(http.ResponseWriter, *http.Request, int)
}

type Endpoint struct {
	handler http.Handler
	cfg     Config
}
type principalKey struct{}
type deadlineKey struct{}

func PrincipalFromContext(ctx context.Context) (authn.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(authn.Principal)
	return p.Clone(), ok
}

func NewProtectedEndpoint(server *mcp.Server, verifier authn.Verifier, cfg Config) (*Endpoint, error) {
	if server == nil || nilVerifier(verifier) || !authn.HTTPSURL(cfg.Resource, true) || len(cfg.AuthorizationServers) == 0 || len(cfg.RequiredScopes) == 0 || cfg.MaxRequestBytes < 1 || cfg.MaxConcurrentRequests < 1 || cfg.MaxConcurrentRequests > 64 || cfg.ReadTimeout <= 0 || cfg.ReadTimeout > 5*time.Minute {
		return nil, errors.New("server, verifier, trust, scopes and bounded limits are required")
	}
	if cfg.Path == "" {
		cfg.Path = "/mcp"
	}
	if !strings.HasPrefix(cfg.Path, "/") || strings.ContainsAny(cfg.Path, "?#") {
		return nil, errors.New("MCP path must be absolute")
	}
	if cfg.MetadataURL == "" {
		cfg.MetadataURL = cfg.Resource + "/.well-known/oauth-protected-resource"
	}
	metadata, err := url.Parse(cfg.MetadataURL)
	if err != nil || !authn.HTTPSURL(cfg.MetadataURL, false) || metadata.Path == "" || metadata.Scheme+"://"+metadata.Host != cfg.Resource {
		return nil, errors.New("metadata URL must belong to the canonical resource")
	}
	for _, issuer := range cfg.AuthorizationServers {
		if !authn.HTTPSURL(issuer, false) {
			return nil, errors.New("HTTPS authorization servers are required")
		}
	}
	for _, scope := range append(slices.Clone(cfg.RequiredScopes), cfg.SupportedScopes...) {
		if !authn.ValidScope(scope) || scope == "offline_access" {
			return nil, errors.New("resource scopes must be valid operation scopes")
		}
	}
	if len(cfg.SupportedScopes) == 0 {
		cfg.SupportedScopes = slices.Clone(cfg.RequiredScopes)
	}
	for _, scope := range cfg.RequiredScopes {
		if !slices.Contains(cfg.SupportedScopes, scope) {
			return nil, errors.New("required scopes must be advertised")
		}
	}
	cfg.RequiredScopes = slices.Clone(cfg.RequiredScopes)
	cfg.SupportedScopes = slices.Clone(cfg.SupportedScopes)
	cfg.AuthorizationServers = slices.Clone(cfg.AuthorizationServers)
	endpoint := &Endpoint{cfg: cfg}
	protocol := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: cfg.MaxRequestBytes})
	withPrincipal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := auth.TokenInfoFromContext(r.Context())
		if info == nil {
			endpoint.reject(w, r, http.StatusUnauthorized)
			return
		}
		principal, ok := info.Extra["principal"].(authn.Principal)
		if !ok {
			endpoint.reject(w, r, http.StatusUnauthorized)
			return
		}
		protocol.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal.Clone())))
	})
	protected := auth.RequireBearerToken(func(ctx context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
		p, err := verifier.Verify(ctx, raw)
		if err != nil || p.Subject == "" || p.ClientID == "" || p.Resource != cfg.Resource || !slices.Contains(cfg.AuthorizationServers, p.Issuer) || p.ExpiresAt.IsZero() || !time.Now().Before(p.ExpiresAt) {
			return nil, auth.ErrInvalidToken
		}
		key, _ := json.Marshal([2]string{p.Issuer, p.Subject})
		return &auth.TokenInfo{UserID: string(key), Scopes: slices.Clone(p.Scopes), Expiration: p.ExpiresAt, Extra: map[string]any{"principal": p.Clone()}}, nil
	}, &auth.RequireBearerTokenOptions{ResourceMetadataURL: cfg.MetadataURL, Scopes: cfg.RequiredScopes})(withPrincipal)
	slots := make(chan struct{}, cfg.MaxConcurrentRequests)
	endpoint.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origins := r.Header.Values("Origin")
		if len(origins) > 1 || len(origins) == 1 && origins[0] != cfg.Resource {
			endpoint.reject(w, r, http.StatusForbidden)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			endpoint.reject(w, r, http.StatusServiceUnavailable)
			return
		}
		protected.ServeHTTP(w, r)
	})
	return endpoint, nil
}

func nilVerifier(v authn.Verifier) bool {
	if v == nil {
		return true
	}
	value := reflect.ValueOf(v)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

func (e *Endpoint) reject(w http.ResponseWriter, r *http.Request, status int) {
	if e.cfg.WriteError != nil {
		e.cfg.WriteError(w, r, status)
		return
	}
	http.Error(w, http.StatusText(status), status)
}

// Handler protects SDK dispatch even when the optional metadata handler is not mounted.
func (e *Endpoint) Handler() http.Handler {
	return e.ReadDeadlineGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != e.cfg.Path {
			e.reject(w, r, http.StatusNotFound)
			return
		}
		e.handler.ServeHTTP(w, r)
	}))
}

func (e *Endpoint) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			e.reject(w, r, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": e.cfg.Resource, "authorization_servers": e.cfg.AuthorizationServers, "scopes_supported": e.cfg.SupportedScopes, "bearer_methods_supported": []string{"header"}})
	})
}

// ReadDeadlineGuard belongs outside response-writer wrappers that do not implement Unwrap.
func (e *Endpoint) ReadDeadlineGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != e.cfg.Path || r.Context().Value(deadlineKey{}) == e {
			next.ServeHTTP(w, r)
			return
		}
		controller := http.NewResponseController(w)
		if controller.SetReadDeadline(time.Now().Add(e.cfg.ReadTimeout)) != nil {
			e.reject(w, r, http.StatusInternalServerError)
			return
		}
		// net/http may drain an unread rejected body after ServeHTTP returns; it resets the deadline before reusing the connection.
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), deadlineKey{}, e)))
	})
}
