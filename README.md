# mcp-go

Protected MCP HTTP transport and access-token verification for Go services, built on the official MCP SDK.
The module owns authentication and request bounds; your service owns tools, application permissions and audit transactions.
MIT licensed.

## Protected endpoint

Register tools directly on the SDK server and supply a verifier that authenticates access tokens on every request.

```go
endpoint, err := mcphttp.NewProtectedEndpoint(server, verifier, mcphttp.Config{
    Resource:              "https://service.example",
    AuthorizationServers:  []string{"https://issuer.example"},
    RequiredScopes:        []string{"read"},
    SupportedScopes:       []string{"read", "write"},
    MaxRequestBytes:       1 << 20,
    MaxConcurrentRequests: 4,
    ReadTimeout:           30 * time.Second,
})
if err != nil {
    return err
}
mux.Handle("/mcp", endpoint.Handler())
mux.Handle("/.well-known/oauth-protected-resource", endpoint.MetadataHandler())
httpServer.Handler = endpoint.ReadDeadlineGuard(mux)
```

Import the root package as `mcphttp "github.com/etamong-playground/mcp-go"` and the verifier contract from `github.com/etamong-playground/mcp-go/authn`.
A missing verifier, invalid trust configuration or invalid limit fails construction.
Stateless Streamable HTTP and JSON responses are the supported transport.
The endpoint does not acquire tokens, accept refresh tokens, store user credentials, retry mutations or implement a client login flow.

Install `ReadDeadlineGuard` outside logging middleware whose response writer does not implement `Unwrap`.
The deadline remains active through the HTTP server's post-handler body drain and is reset by the server before connection reuse.
The endpoint installs a deadline itself when possible; an inaccessible underlying connection produces a closed failure rather than an unbounded body read.
Use the configured MCP path when mounting the endpoint; other paths return 404.

## Verifiers and token profiles

`authn.NewJWTVerifier` discovers a trusted HTTPS issuer, verifies its signature and resource audience, and requires an explicit access-token profile.
It checks subject, expiry, `nbf`, future `iat`, and the client ID extracted by that profile against the configured allowlist.
RS256 is the default signing algorithm; only explicitly supported asymmetric algorithms are accepted.
Discovery and signing-key URLs must use HTTPS and redirects are rejected.
Each issuer response is limited to 1 MiB, after automatic HTTP decompression.
A supplied HTTP client retains its transport, with a bounded timeout and redirects disabled on a private copy.

A valid signature does not distinguish access tokens from ID tokens.
Your profile must enforce the provider's documented access-token discriminator, then return client ID, scopes and selected validated string attributes.
The profile cannot change the verified issuer, audience or lifetime.
Do not use the example's claim names unless they match your issuer's contract.

A custom `authn.Verifier` can implement an application's opaque-token verification or another established access-token contract.
It must verify authenticity, access-token classification, client/resource binding, subject and lifetime before returning a principal.
The endpoint independently rejects missing identity/client, a mismatched issuer/resource and expired principals.
Use `PrincipalFromContext` in tool handlers, then enforce operation scopes, object permissions and account policy in your application.
A principal does not imply administrator authority.

## Configuration and optional capabilities

| Setting or helper | Contract |
| --- | --- |
| `Resource` | Canonical HTTPS origin with a lowercase ASCII DNS name or canonical IP literal and no explicit default port, credentials, path, query or fragment. |
| `AuthorizationServers` | Trusted HTTPS issuer URLs; must include the verified principal's issuer. |
| `RequiredScopes` | Nonempty resource operation scope floor checked before SDK dispatch. |
| `SupportedScopes` | Advertised resource scopes; defaults to required scopes and must include them. |
| `Path` | Absolute MCP endpoint path; defaults to `/mcp`. |
| `MetadataURL` | Same-resource discovery URL; defaults to `/.well-known/oauth-protected-resource`. |
| `MaxRequestBytes` | Required positive encoded HTTP body limit; the application owns decoded/file limits. |
| `MaxConcurrentRequests` | Required capacity between 1 and 64; excess requests return 503. |
| `ReadTimeout` | Required positive body-read timeout, at most five minutes. |
| `WriteError` | Optional rejected-transport response customization; dispatch remains stopped. |
| `MetadataHandler` | Optional helper mounting; your router must still serve discovery at the advertised URL. |
| SDK tools/resources/prompts | Register directly with the SDK when the application needs them. |

`offline_access` belongs to authorization-server/client metadata and is rejected as a resource scope requirement or advertisement.
Native requests may omit `Origin`; a present Origin must exactly match the resource, and multiple Origin values are rejected.
Required authentication, scopes, Origin enforcement, body limits, concurrency and deadlines remain active when optional helpers are omitted.
Keep native-client bootstrap metadata, logging/metrics and semantic durable audit in the application.

## Runnable examples

Both examples bind to `127.0.0.1:8080` and expose a bounded, authenticated `whoami` tool.
Set `MCP_RESOURCE`, `MCP_ISSUER` and `MCP_CLIENT_ID` to the intended resource and issuer registration.
Production HTTPS termination and authorization-server registration remain application responsibilities.

- `go run ./examples/minimal` uses an explicitly provisioned opaque access token from `MCP_BEARER_TOKEN` and a future RFC3339 `MCP_TOKEN_EXPIRY`.
  Supply a random token of at least 32 characters through your private environment; the example binds it to the configured issuer, resource, client and read scope.
- `go run ./examples/authenticated` uses real issuer discovery and JWT verification.
  Its explicit demonstration profile requires `token_use=access`, `client_id` and string `scope` claims.
  Replace that profile with your provider's validated access-token contract and account mapping.

Neither example prints bearer credentials or offers an anonymous mode.
Keep tokens out of source files, tool arguments and logs.

## Validate and release

Run `go build ./...`, `go vet ./...` and `go test -race ./...`.
The build includes the examples; tests exercise real JWT verification, protected protocol calls, identity isolation, negative authorization, body limits and socket deadlines.

Dispatch the `Release` workflow on `main` with an unused `vX.Y.Z` version.
It tests the exact checkout before creating the tag and does not overwrite an existing version.
Consumers pin an immutable version in `go.mod`; do not push release tags manually.
