# Public API

Everything listed here is the public API: it changes only as the deprecation
policy below allows. Everything else in `src/` is marked `@internal` and may
change in any release. `tests/Arch/PublicApiTest.php` fails when a class is
neither `@api` nor `@internal`, or when an `@api` class is missing from this page.

## Classes, interfaces and enums

Public means the class name and its public methods, except a method marked
`@internal`; for enums the case names and backing values (backing values are
wire values). Constructors are public for the data objects (`Data`), events,
exceptions and the `Testing` fakes, which products build; the services and
guards are resolved from the container, so their constructors are not. The
commands are public by name and signature (below), not as PHP classes.

### `Qiick\McpOAuth`

- `AccessTokenAuthenticator` (class)
- `ClientThrottleKey` (class)
- `McpOAuthAdminRoutes` (class)
- `McpOAuthReadiness` (class)
- `McpOAuthRoutes` (class)
- `McpOAuthServer` (class)
- `McpOAuthServiceProvider` (class)
- `McpOAuthSettingsRoutes` (class)
- `RedirectUriGuard` (class)

### `Qiick\McpOAuth\Actions`

- `SwitchMcpOAuthAction` (class)

### `Qiick\McpOAuth\Bridge`

- `FamilyRevokingRefreshTokenRepository` (class)

### `Qiick\McpOAuth\Contracts`

- `AdminSwitch` (interface)
- `ApiKeyDoor` (interface)
- `AuditLogger` (interface)
- `ClientMetadataDocumentFetcherContract` (interface)
- `ConsentProvider` (interface)
- `ConsentView` (interface)
- `GrantAuthorizer` (interface)
- `GrantStore` (interface)
- `InstallationGrantStoreContract` (interface)
- `McpCredentialBinder` (interface)
- `OAuthUserResolver` (interface)

### `Qiick\McpOAuth\Data`

- `AuthorizationDecision` (class)
- `ClientInfo` (class)
- `ClientMetadataDocumentData` (class)
- `CompanionClientDefinitionData` (class)
- `ConsentDecision` (class)
- `ConsentOption` (class)
- `ConsentOptions` (class)
- `ConsentPage` (class)
- `GrantInstallationData` (class)
- `GrantRecord` (class)
- `GrantReplacementData` (class)
- `ProtectedResourceDefinitionData` (class)
- `RevocationReason` (enum)

### `Qiick\McpOAuth\Enums`

- `ClientMetadataFetchStatusEnum` (enum)

### `Qiick\McpOAuth\Erasure`

- `ErasureReport` (class)
- `McpOAuthEraser` (class)
- `OrganisationScopeUnsupportedException` (class)

### `Qiick\McpOAuth\Events`

- `McpClientBlockedEvent` (class)
- `McpClientRegisteredEvent` (class)
- `McpConsentApprovedEvent` (class)
- `McpConsentDeniedEvent` (class)
- `McpGrantRevokedEvent` (class)
- `McpOAuthDisabledEvent` (class)
- `McpOAuthEnabledEvent` (class)
- `McpPassportKeysFoundMissingEvent` (class)
- `McpRedirectHostBlockedEvent` (class)
- `McpRedirectHostUnblockedEvent` (class)
- `McpRefreshTokenReusedEvent` (class)
- `McpRevokedRecordsPurgedEvent` (class)
- `McpTokenRevokedEvent` (class)
- `McpUnusedClientsPrunedEvent` (class)
- `SubjectErasedEvent` (class)

### `Qiick\McpOAuth\Exceptions`

- `InvalidMcpOAuthConfigException` (class)
- `McpOAuthCannotBeEnabledException` (class)
- `MissingPassportKeysException` (class)

### `Qiick\McpOAuth\Http\Middleware`

- `McpBearerDoorMiddleware` (class)
- `McpChallengeMiddleware` (class)

### `Qiick\McpOAuth\Testing`

- `FakeAdminSwitch` (class)
- `FakeApiKeyDoor` (class)
- `FakeAuditLogger` (class)
- `FakeConsentProvider` (class)
- `FakeGrantAuthorizer` (class)
- `FakeGrantStore` (class)
- `FakeMcpCredentialBinder` (class)

## Additional protected resources

Register each `ProtectedResourceDefinitionData` with
`McpOAuthServer::registerResource()` before `McpOAuthRoutes::register()` or
the first resolution of Passport's authorization server. Each definition has
an exact path under the issuer, one distinct wire scope and server-assigned client
classes. The matching nested RFC 9728 route serves its metadata.

An indicator compares scheme and host case-insensitively, permits one trailing
slash and preserves path case. Responses and grant records use the canonical
registered identifier.

Products that enable an additional resource persist
`ConsentDecision::resourceScopes` unchanged and return it in
`GrantRecord::resourceScopes` on all reads. Legacy MCP-only grants may
return an empty map. Use `AccessTokenAuthenticator::authenticate()` with the
registered identifier as its second argument at the product endpoint.

## Companion installation grants

Register a first-party Companion identity during product boot using
`McpOAuthServer::registerCompanionClient(CompanionClientDefinitionData)`.
The server reserves its exact CIMD identifier for the shipped name,
operator and claimed HTTPS callbacks. The pinned client is public and uses
authorization code with PKCE and refresh. Turning off
`companion.enabled` refuses authorize, token and bearer requests for the
identity. The shipped definition remains reserved.

An enrolled per-install client sends its random `install_id` as a UUIDv4 and
`companion_jkt` as the 43-character base64url SHA-256 JWK thumbprint. The
package normalizes the UUID to lowercase. After consent,
`ConsentDecision::installation` includes the organisation chosen by the user.

Products opt in by binding an `InstallationGrantStoreContract` as their
`GrantStore`. Its replacement method atomically re-consents the exact
client, user, organisation and installation tuple. The new grant carries
the same installation and the consent time. Return the prior grant when
present so the package can retire its credentials. Ordinary clients keep
the existing `GrantStore::replace()` contract.

After the absolute grant deadline, the first attempted bearer or refresh use
revokes the installation grant and its credentials with `RevocationReason::Expired`.
Return that stored reason on reads of revoked installation grants.

## Config keys and environment variables

Every key of `config/mcp-oauth.php` (published with the `mcp-oauth-config` tag),
with the variable that sets it where there is one:

| Key | Variable |
| --- | --- |
| `enabled` | `MCP_OAUTH_ENABLED` |
| `mcp_enabled` | none: the product's own MCP flag |
| `mcp_path` | none |
| `access_token_ttl_minutes` | `MCP_OAUTH_ACCESS_TOKEN_TTL_MINUTES` |
| `refresh_token_ttl_days` | `MCP_OAUTH_REFRESH_TOKEN_TTL_DAYS` |
| `auth_code_ttl_minutes` | `MCP_OAUTH_AUTH_CODE_TTL_MINUTES` |
| `companion.enabled` | `MCP_OAUTH_COMPANION_ENABLED` (false by default) |
| `companion.grant_max_age_days` | `MCP_OAUTH_COMPANION_GRANT_MAX_AGE_DAYS` (180 by default, 1–3650) |
| `registrations_per_minute` | `MCP_OAUTH_REGISTRATIONS_PER_MINUTE` |
| `authorize_requests_per_minute` | `MCP_OAUTH_AUTHORIZE_REQUESTS_PER_MINUTE` |
| `authorize_requests_per_client_per_minute` | `MCP_OAUTH_AUTHORIZE_REQUESTS_PER_CLIENT_PER_MINUTE` |
| `token_requests_per_minute` | `MCP_OAUTH_TOKEN_REQUESTS_PER_MINUTE` |
| `token_requests_per_client_per_minute` | `MCP_OAUTH_TOKEN_REQUESTS_PER_CLIENT_PER_MINUTE` |
| `revoke_requests_per_minute` | `MCP_OAUTH_REVOKE_REQUESTS_PER_MINUTE` |
| `revoke_requests_per_client_per_minute` | `MCP_OAUTH_REVOKE_REQUESTS_PER_CLIENT_PER_MINUTE` |
| `revocation_enabled` | `MCP_OAUTH_REVOCATION_ENABLED` |
| `registrations_global_cap` | `MCP_OAUTH_REGISTRATIONS_GLOBAL_CAP` |
| `unused_client_retention_hours` | `MCP_OAUTH_UNUSED_CLIENT_RETENTION_HOURS` |
| `revoked_retention_days` | `MCP_OAUTH_REVOKED_RETENTION_DAYS` |
| `mcp_auth_failures_per_minute` | `MCP_OAUTH_MCP_AUTH_FAILURES_PER_MINUTE` |
| `host_block_chunk_size` | none |
| `spec_revision` | `MCP_OAUTH_SPEC_REVISION` |
| `cimd.enabled` | `MCP_OAUTH_CIMD_ENABLED` |
| `cimd.max_document_bytes` | `MCP_OAUTH_CIMD_MAX_DOCUMENT_BYTES` |
| `cimd.timeout_seconds` | `MCP_OAUTH_CIMD_TIMEOUT_SECONDS` |
| `cimd.cache_min_seconds` | `MCP_OAUTH_CIMD_CACHE_MIN_SECONDS` |
| `cimd.cache_max_seconds` | `MCP_OAUTH_CIMD_CACHE_MAX_SECONDS` |
| `grant_binding_column` | none |
| `user_model` | none |
| `migrations.load` | `MCP_OAUTH_LOAD_MIGRATIONS` |

## Commands

- `mcp-oauth:check`: reports the switch, issuer, resource, keys and routes. It
  exits 1 beside a foreign Passport route or one of laravel/mcp's OAuth routes,
  whatever the switch, and when OAuth is on but not ready or not served at the
  origin; with OAuth off it exits 0 otherwise.
- `mcp-oauth:prune-auth-code-exchanges {--dry-run}`
- `mcp-oauth:prune-unused-clients {--dry-run}`
- `mcp-oauth:purge-revoked {--dry-run}`

## Events

Every class in `Qiick\McpOAuth\Events` above. The audit entry names written
through `AuditLogger` (`oauth_consent_approved`, `oauth_grant_revoked`, …) are
public too; `docs/audit.md` lists them with their properties.

## Routes

`McpOAuthRoutes::register()` mounts, at the origin (Laravel adds `HEAD` to
every `GET`; `{mcp_path}` is `mcp-oauth.mcp_path`):

| Method | URI | Name |
| --- | --- | --- |
| `GET` | `/.well-known/oauth-authorization-server` and `/.well-known/oauth-authorization-server/{mcp_path}` | `mcp.oauth.authorization-server`, `mcp.oauth.authorization-server.mcp` |
| `GET` | `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/{mcp_path}` | `mcp.oauth.protected-resource`, `mcp.oauth.protected-resource.mcp` |
| `POST` | `/oauth/register` | `mcp.oauth.register` |
| `GET`, `POST`, `DELETE` | `/oauth/authorize` | `passport.authorizations.authorize`, `.approve`, `.deny` |
| `PUT`, `PATCH`, `OPTIONS` | `/oauth/authorize` (answers 405) | `passport.authorizations.unsupported-method` |
| `POST` | `/oauth/token` | `passport.token` |
| `POST` | `/oauth/revoke` (when `revocation_enabled`) | `mcp.oauth.revoke` |

`McpOAuthAdminRoutes::register($permissionMiddleware)` mounts, inside the
product's group, under `mcp-oauth-clients` with names `mcp-oauth.admin.*`:
`GET /` (`index`), `POST {clientId}/block` (`block`), `POST bulk-block`
(`bulk-block`), `POST prune-unused` (`prune-unused`), `POST blocked-hosts`
(`blocked-hosts.store`) and `DELETE blocked-hosts/{blockedHostId}`
(`blocked-hosts.destroy`).
`McpOAuthSettingsRoutes::register()` mounts Connected apps under
`settings/connected-apps` with names `mcp-oauth.connected-apps.*`: `GET /`
(`index`) and `DELETE {grantId}` (`destroy`). The README describes each.

## Tables

The package's migrations create `oauth_client_metadata`,
`oauth_blocked_redirect_hosts`, `oauth_consent_records` and
`oauth_auth_code_exchanges`, with the columns in `docs/reference-schema.md`.
Passport's own tables stay as Passport publishes them, plus the product's grant
binding column on `oauth_access_tokens` (`grant_binding_column`).

## Error codes

The `error` values on the wire are OAuth's, by surface. Every OAuth endpoint
also answers `temporarily_unavailable` (503) while the Passport keys are
missing.

| Surface | `error` values |
| --- | --- |
| `GET /oauth/authorize` (RFC 6749 §4.1.2.1, RFC 8707) | `invalid_request`, `invalid_client`, `unsupported_response_type`, `invalid_target`; `access_denied` on a denial (league) |
| `POST /oauth/token` (RFC 6749 §5.2, RFC 8707) | `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `invalid_scope`, `invalid_target`, and league's `server_error` |
| `POST /oauth/register` (RFC 7591 §3.2.2) | `invalid_request`, `invalid_client_metadata`, `invalid_redirect_uri` |
| `POST /oauth/revoke` (RFC 7009 §2.2.1) | `invalid_request`, `invalid_client` |
| `/mcp` Bearer challenge (RFC 6750 §3.1) | `invalid_token` (401), `insufficient_scope` (403) |

The token and revocation error descriptions are league's fixed strings. On
`/mcp`, `insufficient_scope` carries the description the product's
`GrantAuthorizer` returns.

## Deprecation policy

This package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

- **Deprecation in minor releases:** a deprecated public API (class, method,
  interface, config key, environment variable, command, event, route) is marked
  `@deprecated`, listed in `CHANGELOG.md` under `Deprecated` and in
  `UPGRADING.md` with its replacement, and keeps working for at least one minor
  release.
- **Removal in major releases only:** nothing public is removed or changed
  incompatibly within a major version; removals wait for the next major.
- **Before 1.0.0:** a minor or a pre-release may break; every break is in
  `UPGRADING.md` before the tag. From `1.0.0` on, the API and the migrations are
  frozen and follow SemVer.
