package mcphttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/etamong-playground/mcp-go/authn"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func config() Config {
	return Config{Resource: "https://service.example", AuthorizationServers: []string{"https://issuer.example"}, RequiredScopes: []string{"read"}, SupportedScopes: []string{"read", "write"}, MaxRequestBytes: 1024, MaxConcurrentRequests: 1, ReadTimeout: 100 * time.Millisecond}
}
func principal() authn.Principal {
	return authn.Principal{Issuer: "https://issuer.example", Resource: "https://service.example", Subject: "fixture", ClientID: "native", Scopes: []string{"read"}, ExpiresAt: time.Now().Add(time.Hour)}
}
func server() *mcp.Server { return mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil) }
func verifier() authn.Verifier {
	return authn.VerifierFunc(func(_ context.Context, raw string) (authn.Principal, error) {
		if raw != "fixture" {
			return authn.Principal{}, authn.ErrInvalidToken
		}
		return principal(), nil
	})
}

type deadlineWriter struct{ *httptest.ResponseRecorder }

func (w deadlineWriter) SetReadDeadline(time.Time) error { return nil }
func request(endpoint *Endpoint, token, origin string) (int, http.Header) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := deadlineWriter{httptest.NewRecorder()}
	endpoint.Handler().ServeHTTP(w, r)
	return w.Code, w.Header()
}

func TestProtectedEndpointRejectsInvalidConfiguration(t *testing.T) {
	for name, change := range map[string]func(*Config){"resource": func(c *Config) { c.Resource = "http://service.example" }, "issuer": func(c *Config) { c.AuthorizationServers = nil }, "scope": func(c *Config) { c.RequiredScopes = nil }, "refresh requirement": func(c *Config) { c.RequiredScopes = []string{"offline_access"} }, "unadvertised scope": func(c *Config) { c.RequiredScopes = []string{"admin"} }, "body": func(c *Config) { c.MaxRequestBytes = 0 }, "concurrency": func(c *Config) { c.MaxConcurrentRequests = 0 }, "too many": func(c *Config) { c.MaxConcurrentRequests = 65 }, "timeout": func(c *Config) { c.ReadTimeout = 0 }, "metadata": func(c *Config) { c.MetadataURL = "https://wrong.example/meta" }} {
		t.Run(name, func(t *testing.T) {
			cfg := config()
			change(&cfg)
			if _, err := NewProtectedEndpoint(server(), verifier(), cfg); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	var typedNil *authn.JWTVerifier
	var functionNil authn.VerifierFunc
	for _, v := range []authn.Verifier{nil, typedNil, functionNil} {
		if _, err := NewProtectedEndpoint(server(), v, config()); err == nil {
			t.Fatal("missing verifier accepted")
		}
	}
	if _, err := NewProtectedEndpoint(nil, verifier(), config()); err == nil {
		t.Fatal("missing SDK server accepted")
	}
}

func TestAuthenticationIsRequiredWithoutMetadata(t *testing.T) {
	endpoint, err := NewProtectedEndpoint(server(), verifier(), config())
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "invalid"} {
		status, headers := request(endpoint, token, "")
		if status != 401 || !strings.Contains(headers.Get("WWW-Authenticate"), "https://service.example/.well-known/oauth-protected-resource") {
			t.Fatalf("missing credential accepted: %d", status)
		}
	}
	if status, _ := request(endpoint, "fixture", ""); status != 200 {
		t.Fatalf("native authorized request rejected: %d", status)
	}
	if status, _ := request(endpoint, "fixture", "https://service.example"); status != 200 {
		t.Fatal("canonical Origin rejected")
	}
	if status, _ := request(endpoint, "fixture", "https://untrusted.example"); status != 403 {
		t.Fatal("untrusted Origin accepted")
	}
}

func TestPrincipalTrustAndScopes(t *testing.T) {
	for name, change := range map[string]func(*authn.Principal){"subject": func(p *authn.Principal) { p.Subject = "" }, "resource": func(p *authn.Principal) { p.Resource = "https://other.example" }, "issuer": func(p *authn.Principal) { p.Issuer = "https://other.example" }, "client": func(p *authn.Principal) { p.ClientID = "" }, "expiry": func(p *authn.Principal) { p.ExpiresAt = time.Now().Add(-time.Second) }, "scope": func(p *authn.Principal) { p.Scopes = []string{"write"} }} {
		t.Run(name, func(t *testing.T) {
			v := authn.VerifierFunc(func(context.Context, string) (authn.Principal, error) { p := principal(); change(&p); return p, nil })
			e, err := NewProtectedEndpoint(server(), v, config())
			if err != nil {
				t.Fatal(err)
			}
			status, headers := request(e, "fixture", "")
			want := 401
			if name == "scope" {
				want = 403
			}
			if status != want {
				t.Fatalf("invalid principal accepted: %d", status)
			}
			if strings.Contains(headers.Get("WWW-Authenticate"), "offline_access") {
				t.Fatal("refresh scope leaked into challenge")
			}
		})
	}
}

func TestMetadataAndConfigOwnership(t *testing.T) {
	cfg := config()
	e, err := NewProtectedEndpoint(server(), verifier(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RequiredScopes[0] = "changed"
	cfg.SupportedScopes[0] = "changed"
	cfg.AuthorizationServers[0] = "https://other.example"
	if status, _ := request(e, "fixture", ""); status != 200 {
		t.Fatal("caller config mutation changed trust")
	}
	w := httptest.NewRecorder()
	e.MetadataHandler().ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil))
	var metadata struct {
		Resource string   `json:"resource"`
		Issuers  []string `json:"authorization_servers"`
		Scopes   []string `json:"scopes_supported"`
	}
	if json.Unmarshal(w.Body.Bytes(), &metadata) != nil || metadata.Resource != "https://service.example" || metadata.Issuers[0] != "https://issuer.example" || len(metadata.Scopes) != 2 {
		t.Fatal("metadata contract changed")
	}
}

type opaqueWriter struct{ http.ResponseWriter }

func TestOuterReadDeadlineGuardAndFailureResponse(t *testing.T) {
	e, _ := NewProtectedEndpoint(server(), verifier(), config())
	w := httptest.NewRecorder()
	e.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/mcp", nil))
	if w.Code != 500 {
		t.Fatal("uninstallable deadline did not fail closed")
	}
	wrapped := e.ReadDeadlineGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.Handler().ServeHTTP(opaqueWriter{w}, r) }))
	host := httptest.NewServer(wrapped)
	defer host.Close()
	resp, err := http.Post(host.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("outer guard failed across opaque writer: %d", resp.StatusCode)
	}
}

func TestSlowBodyReleasesCapacityAndRejectsOversizedPayload(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	v := authn.VerifierFunc(func(context.Context, string) (authn.Principal, error) {
		once.Do(func() { close(entered) })
		return principal(), nil
	})
	cfg := config()
	cfg.ReadTimeout = 500 * time.Millisecond
	e, _ := NewProtectedEndpoint(server(), v, cfg)
	host := httptest.NewServer(e.Handler())
	defer host.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(host.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer fixture\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: 500\r\n\r\n{", strings.TrimPrefix(host.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("slow request never acquired the authenticated slot")
	}
	send := func(body string) *http.Response {
		r, _ := http.NewRequest("POST", host.URL+"/mcp", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer fixture")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		client := http.Client{Timeout: time.Second}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := send("{}")
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("saturation not enforced: %d", resp.StatusCode)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(conn)
	resp = send(strings.Repeat("x", 2048))
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("capacity/body cap failed: %d", resp.StatusCode)
	}
	resp = send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("slot not released: %d", resp.StatusCode)
	}
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header = r.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(copy)
}

func TestSDKProtocolKeepsCallerIdentitiesIsolated(t *testing.T) {
	sdk := server()
	mcp.AddTool(sdk, &mcp.Tool{Name: "whoami", Description: "Read authenticated identity", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]string, error) {
		p, ok := PrincipalFromContext(ctx)
		if !ok {
			return nil, nil, authn.ErrInvalidToken
		}
		return nil, map[string]string{"subject": p.Subject}, nil
	})
	v := authn.VerifierFunc(func(_ context.Context, token string) (authn.Principal, error) {
		if token != "alice" && token != "bob" {
			return authn.Principal{}, authn.ErrInvalidToken
		}
		p := principal()
		p.Subject = token
		return p, nil
	})
	cfg := config()
	cfg.MaxConcurrentRequests = 4
	cfg.ReadTimeout = time.Second
	endpoint, err := NewProtectedEndpoint(sdk, v, cfg)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewServer(endpoint.Handler())
	defer host.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sessions := map[string]*mcp.ClientSession{}
	for _, subject := range []string{"alice", "bob"} {
		client := mcp.NewClient(&mcp.Implementation{Name: "identity-client", Version: "1"}, nil)
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: host.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{subject}, Timeout: time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		sessions[subject] = session
		tools, err := session.ListTools(ctx, nil)
		if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "whoami" || tools.Tools[0].Annotations == nil || !tools.Tools[0].Annotations.ReadOnlyHint {
			t.Fatal("SDK tool contract not preserved")
		}
	}
	var group sync.WaitGroup
	for subject, session := range sessions {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 4 {
				result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "whoami", Arguments: map[string]any{}})
				if err != nil || result.IsError {
					t.Errorf("authenticated SDK call failed: %v", err)
					return
				}
				raw, _ := json.Marshal(result.StructuredContent)
				var out map[string]string
				if json.Unmarshal(raw, &out) != nil || out["subject"] != subject {
					t.Errorf("identity mixed between callers: %s", raw)
					return
				}
			}
		}()
	}
	group.Wait()
	r, _ := http.NewRequest("POST", host.URL+"/mcp", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer alice")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "1900-01-01")
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatal("unsupported protocol accepted")
	}
}

func TestOptionalRejectionHookCannotDispatchAndPathCannotSkipDeadline(t *testing.T) {
	cfg := config()
	rejected := false
	cfg.WriteError = func(w http.ResponseWriter, _ *http.Request, status int) {
		rejected = true
		w.Header().Set("X-Transport-Denied", "true")
		w.WriteHeader(status)
	}
	e, err := NewProtectedEndpoint(server(), verifier(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	status, headers := request(e, "fixture", "https://untrusted.example")
	if status != 403 || !rejected || headers.Get("X-Transport-Denied") != "true" {
		t.Fatal("rejection hook not applied")
	}
	for _, origins := range [][]string{{""}, {"https://service.example", "https://untrusted.example"}} {
		r := httptest.NewRequest("POST", "/mcp", nil)
		r.Header["Origin"] = origins
		w := deadlineWriter{httptest.NewRecorder()}
		e.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("invalid Origin accepted")
		}
	}
	w := httptest.NewRecorder()
	e.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/other", nil))
	if w.Code != 404 {
		t.Fatal("incorrect mount path reached SDK without deadline")
	}
}

func TestRejectedSlowBodyRemainsBounded(t *testing.T) {
	e, err := NewProtectedEndpoint(server(), verifier(), config())
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewServer(e.Handler())
	defer host.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(host.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer invalid\r\nContent-Length: 100\r\n\r\nx", strings.TrimPrefix(host.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	raw, err := io.ReadAll(conn)
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("rejected request kept unread body alive beyond deadline")
	}
	if !strings.Contains(string(raw), "401 Unauthorized") {
		t.Fatalf("missing rejection: %q %v", raw, err)
	}
}
