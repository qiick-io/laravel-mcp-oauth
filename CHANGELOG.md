# Changelog

All notable changes to **laravel-mcp-oauth** (`qiick/laravel-mcp-oauth`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- DCR answers with `client_id_issued_at` (epoch seconds), which RFC 7591
  §3.2.1 requires, and stores and returns `application_type`, `tos_uri`,
  `policy_uri`, `contacts`, `software_id` and `software_version`. A client that
  sends no `application_type` gets `native` when every redirect URI is
  loopback http or a private-use scheme, `web` otherwise. `tos_uri` and
  `policy_uri` follow the `logo_uri` rules (https, public host); an unknown
  `application_type`, more than ten contacts or an over-long value is a 400
  `invalid_client_metadata`.
- At `/mcp`, a token signed with the server key but without a `scopes` claim,
  or with a null one, is refused as `invalid_token` instead of answering 500.
  A scope that is not exactly `mcp:use` is compared strictly, never cast.
- `AccessTokenAuthenticator::authenticate()` checks the Bearer of the request
  it is given, not the container's current request. Its constructor no longer
  takes the container.
- Every integer config key is a raw env string validated at boot:
  `registrations_global_cap`, `unused_client_retention_hours`,
  `revoked_retention_days` and the `cimd.*` numbers no longer go through
  `(int) env()`, which read `1e3` as 1000 and `abc` as 0. Boot fails closed
  outside 1..the documented maximum (new maxima for unused-client retention
  and CIMD). A PHP int still works; an app that published the config file
  drops the `(int)` casts there to get the stricter check.
- A blocked host with `match_mode = exact` blocks the host only; until now
  it blocked its subdomains too. Any other mode, a typo included, still
  blocks the subdomains.
- The DCR global cap counts `Passport::client()`, the model Passport writes
  to, so a product's `Passport::useClientModel()` no longer bypasses it.
- `McpOAuthServer::acceptsResource()` compares the resource path exactly
  (RFC 8707), so `https://app.example/API/MCP` and
  `https://app.example/api/mcp` are different resources. Scheme and host stay
  case-insensitive, as the MCP spec asks. One trailing slash is ignored, and
  no more than one.
- `mcp_path = '/'` falls back to `mcp` like an empty path, instead of making
  the resource the bare origin, which no request could ever match.
- Boot refuses `cimd.cache_min_seconds` above `cimd.cache_max_seconds`.
- `ClientMetadataUriGuard` starts from `RedirectUriGuard::parseCanonical()`
  (now public) and refuses internal names (single-label, `localhost`,
  `*.local`, `*.internal`), IPv6 literals embedding IPv4 (mapped, translated,
  NAT64, 6to4), non-ASCII hosts, alternative IPv4 spellings, CGNAT,
  benchmarking, IETF-protocol and multicast ranges.
- `RedirectUriGuard` refuses every host whose last label is numeric unless it
  is four decimal octets of 0..255 (WHATWG reads `0177.0.0.1` as octal
  127.0.0.1); the rule no longer depends on glibc vs macOS `inet_pton`.
- `ClientMetadataUriGuard` also refuses Teredo, documentation (`2001:db8::/32`,
  TEST-NET-1/2/3), discard (`100::/64`) and the former 6to4 relay range, plus
  `*.lan` and `home.arpa`. `RedirectUriGuard` refuses the unspecified
  addresses `0.0.0.0` and `::` for every scheme; `parseCanonical()` is
  `@internal` (parsing only, not validation).
- DCR `client_name` fails closed on invalid UTF-8 or a PCRE error, and refuses
  line / paragraph separators, Hangul fillers and names that render as nothing
  (spaces, combining marks or VS16 alone, U+2800); the `name` alias gets the
  same policy.
- `RedirectUriGuard` uses one canonical parse for registration, scheme, hostOf
  and blocklist (refuse fragment, backslash, userinfo); non-loopback `http` is
  refused at registration (RFC 8252); leading-zero IPv4 octets throw a
  glibc-independent message.
- `RedirectUriGuard` refuses hostless `http(s)` redirect URIs (`https:///…`,
  `https:/…`, …) and canonicalises IPv6 / unmaps `::ffff:` so alternate
  spellings hit the same block; non-dotted-decimal IPv4 forms are refused.
- `McpOAuthServer`: a throwing `AdminSwitch` counts as OFF (S11); `isReady`
  requires an absolute `app.url`; `mcp_path` trailing slashes normalised.
- `ClientThrottleKey` excludes `::/127` from IPv4-compatible unmapping and
  unmaps `::ffff:0:a.b.c.d` plus `64:ff9b:1::/48`.

### Added

- `SwitchMcpOAuthAction` (design §4.3): the product's settings page switches
  OAuth on or off through it. Switching on is refused with
  `McpOAuthCannotBeEnabledException` (the reason to show) while the Passport
  keys are missing, APP_URL is not absolute or a foreign `passport.*` route
  exists; either way the product's store is written through a callback and
  `McpOAuthEnabled` / `McpOAuthDisabled` is dispatched with the actor.
- The consent page's `client` carries `isRedirectLoopbackOnly` (S3): every
  redirect URI is loopback http, so the page can warn that the code goes to a
  program on the user's computer. `ClientInfo` gains the same flag, and
  `RedirectUriGuard::isLoopbackRedirectUri()` and
  `McpOAuthServer::hasAbsoluteIssuer()` are public.
- `McpOAuthServer` exposes the discovery contract (standards review M9):
  `specRevision()` (the `spec_revision` config, a `YYYY-MM-DD` date, failing
  closed otherwise), `authorizationServerMetadata()` and
  `protectedResourceMetadata()` (the RFC 8414 and RFC 9728 documents the
  well-known routes now serve unchanged), `revocationEndpointUrl()` and
  `supportsClientIdMetadataDocuments()` (false until the CIMD fetcher lands,
  whatever `cimd.enabled` says).
- `revocation_enabled` config (`MCP_OAUTH_REVOCATION_ENABLED`, default true),
  a boolean read like `FILTER_VALIDATE_BOOLEAN` (`true`, `1`, `on`, `yes`):
  any other value leaves `POST oauth/revoke` unregistered and drops
  `revocation_endpoint` from the metadata.
- `oauth_auth_code_exchanges` carries `metadata` (json, null) and
  `schema_version` (default 1) like every package table (M7); it keeps the
  code id as its key, the one documented exception to UUID ids. Pre-1.0 the
  `create_` migration changed: run `migrate:fresh` on a local database.
- Admin backend for MCP clients and redirect hosts (design §5.2, §8.2):
  `BlockClientAction`, `BulkBlockClientsAction` (1–100 distinct ids),
  `BlockRedirectHostAction` (UTS #46 to ASCII, exact or with subdomains,
  chunked by `host_block_chunk_size`) and `UnblockRedirectHostAction`, with
  their events, behind `McpOAuthAdminRoutes::register($permissionMiddleware)`.
  Only clients the package registered are listed or blocked.
- Authorization endpoint and consent (design §8.3): `GET|POST|DELETE
  oauth/authorize` (`passport.authorizations.*`) inside the off-gate (404
  identical to a missing route, HTML 503 for a browser when keys are missing),
  with `web`, `throttle:mcp-oauth-authorize` and `frame-ancestors 'none'` /
  `X-Frame-Options: DENY`; approve and deny also need `auth` and `verified`,
  and CSRF comes from `web`. `ValidateAuthorizationRequestMiddleware` requires
  `response_type=code`, PKCE `S256` with a challenge, the exact `resource`, an
  active unblocked client and a `redirect_uri` exactly equal to a registered
  one under `RedirectUriGuard` (the port counts on loopback too); every refusal
  is a JSON 400, never a redirect (RFC 6749 §4.1.2.1). Foreign wire scopes are
  dropped. Consent is asked every time. Approve and deny need the pending
  request of the signed-in user and its `auth_token` (else 403) and write one
  `oauth_consent_records` row each (`denied` kept 90 days); approve judges the
  posted scopes, role, resources and organisation against
  `ConsentProvider::options()`, then `validate()`, replaces the grant, revokes
  the earlier codes and tokens of that client and user, and dispatches
  `McpConsentApproved`; deny dispatches `McpConsentDenied`. Every redirect to
  the client carries `state` and `iss` (RFC 9207); an Inertia visit leaves
  with `X-Inertia-Location`. `ConsentOptions::$organisations` (instituta: the
  user picks one when they have several). Default `InertiaConsentView` renders
  `oauth/authorize` when Inertia is installed; props and form fields are in
  `docs/consent-page.md`. `FakeConsentProvider`, and `FakeGrantStore::replace()`.
- Token endpoint (design §5.2 item 6, §8.4): `POST oauth/token`
  (`passport.token`) inside the off-gate, stateless, with
  `throttle:mcp-oauth-token` and `ValidateTokenRequestMiddleware`: only the
  `authorization_code` (PKCE `S256`) and `refresh_token` grants, even when
  Passport enables another one; the exact `resource` on both; a client named
  in the body or in HTTP Basic must be a UUID with no blocked redirect host.
  Every refusal is one fixed RFC 6749 §5.2 body per error code with no `hint`;
  league's code, client and redirect mismatches answer `invalid_grant`.
  `AccessTokenCreated` binds each new token to `GrantStore::activeFor()`
  (`bindingKey()` in `grant_binding_column`, `audience` = the MCP resource) or
  revokes it at once when no grant is active (S54).
- One-shot authorization codes (RFC 9700 §4.5): `OneShotAuthCodeRepository`
  consumes a code with an atomic update the first time league asks about it,
  so a failed exchange (wrong verifier, redirect URI or client) burns it and
  only one of two parallel exchanges wins. A code presented again, before or
  after it expired, revokes the grant it was consumed under and every token
  bound to it (RFC 6749 §4.1.2), never a newer consent's; new package table
  `oauth_auth_code_exchanges` records that grant. The grant is revoked before
  its tokens, an already revoked grant is left as it is, and the token of a
  code exchange is bound to the grant its code was consumed under.
- Only MCP clients reach `oauth/authorize` and `oauth/token`: a Passport
  client with no `oauth_client_metadata` row is refused as `invalid_client`,
  so every token minted there is bound. **Upgrade:** clients registered via
  DCR before this version have no row and are refused; they must register
  again (or the product backfills a `registration_source = dcr` row for them).
  DCR writes the client and its row in one transaction;
  `oauth_client_metadata` and `oauth_auth_code_exchanges` live on
  `passport.connection`, like Passport's tables. With `mcp-oauth.enabled` off,
  Passport keeps its own auth-code and refresh-token repositories and needs no
  `GrantStore`.
- Only tokens of MCP clients are bound, and only while `mcp-oauth.enabled` is
  on. An MCP client is one with an `oauth_client_metadata` row, which DCR now
  writes (`registration_source = dcr`, `token_endpoint_auth_method = none`,
  `client_id_issued_at`, and the `logo_uri` / `client_uri` it echoes, https
  only); the
  product's own Passport clients and their `createToken()` tokens are left
  alone. A token is bound first and its grant read again, so a concurrent
  replay of its code always ends with the token revoked. While OAuth is on,
  the AuthorizationServer keeps only the MCP grants (password, implicit and
  client credentials are removed even if Passport enables them); off, the
  product's Passport grants stay.
  The token endpoint refuses HTTP Basic and body credentials together
  (RFC 6749 §2.3), challenges in the scheme the client used, and the
  per-client throttle keys on the body (query for authorize) or Basic id,
  lower-cased.
- Token revocation (RFC 7009): `POST oauth/revoke` (`mcp.oauth.revoke`) inside
  the off-gate, stateless, `throttle:mcp-oauth-revoke`; client authentication
  as at the token endpoint (registered clients only, never Basic and body
  together, a confidential client's secret checked). A refresh token revokes
  its family and the grant (new `RevocationReason::Client`); an access token
  revokes itself and the refresh tokens issued with it, not the grant. The
  refresh tokens are deleted, so a later presentation is refused as unknown and
  never read as reuse. A dead refresh token is judged as `oauth/token` judges
  it: expired or unknown changes nothing; a rotated one is reuse (family and
  grant revoked under `RevocationReason::Reuse`). The body must be
  form-encoded. Always 200 for unknown, forged, dead or foreign tokens.
  New event `McpTokenRevoked`.
- Discovery (RFC 8414, RFC 9728): `/.well-known/oauth-authorization-server`
  and `/.well-known/oauth-protected-resource`, each at the root and the MCP
  path only, built from `APP_URL`, 404 with OAuth off. The `/mcp` 401 challenge
  of laravel/mcp is left as if the package were absent (no `resource_metadata`
  pointing at a document that may be off). They replace
  `Mcp::oauthRoutes()`, which a product must not call.
- Retention (standards review M5): `mcp-oauth:purge-revoked {--dry-run}`
  deletes, 90 days (`revoked_retention_days`) after revocation and never
  sooner, the clients the package registered (with their codes and tokens),
  the product's grants through the new `GrantStore::purgeRevokedBefore()`,
  and consent records past `retention_until` (an approval whose grant is no
  longer active gets its clock started); event `McpRevokedRecordsPurged`.
  `mcp-oauth:prune-unused-clients {--dry-run}` deletes DCR clients nobody
  authorised within 24 hours, in chunks, never a client in retention or a
  product's own Passport client; event `McpUnusedClientsPruned`. A client a
  user once approved is never pruned: `oauth_client_metadata` gains
  `first_authorized_at`, set at the first approval and kept after the grant is
  purged (the `create_` migration changed: run `migrate:fresh` locally).
  `mcp-oauth:check` reports the gate, issuer, resource, key source and
  foreign Passport routes, and exits 1 when OAuth is on but not ready.
- `mcp-oauth:prune-auth-code-exchanges {--dry-run}` deletes the
  `oauth_auth_code_exchanges` rows whose grant is revoked or gone.
- The `/mcp` Bearer door (design §5.3, §8.5): `McpBearerDoorMiddleware`
  selects the product's `ApiKeyDoor` or the package's `AccessTokenAuthenticator`
  (`@api`), which re-checks on every call the token, its audience, the client
  (registered, not revoked, no blocked host), the bound active grant, the wire
  scope `mcp:use` and the product's `GrantAuthorizer`; refusals are RFC 6750
  `invalid_token` (expired, revoked or not valid) or the product's
  `insufficient_scope`. A per-address failure brake answers 429 before the
  credential is read. `McpChallengeMiddleware` replaces laravel/mcp's
  `AddWwwAuthenticateHeader`: OAuth off, the plain challenge as before; on,
  `resource_metadata` from `APP_URL` and `scope="mcp:use"` when no credential
  was sent. With OAuth on, boot also requires `GrantAuthorizer`, `ApiKeyDoor`
  and `McpCredentialBinder`. Test doubles: `FakeApiKeyDoor`,
  `FakeMcpCredentialBinder`, `FakeGrantAuthorizer`.
- Fail-closed boot (S81): with `mcp-oauth.enabled` on, boot throws
  `InvalidMcpOAuthConfigException` naming a missing `ConsentView`,
  `ConsentProvider` or `GrantStore` binding.

- `mcp_auth_failures_per_minute` kept as a raw env string and validated with
  `BoundedPositiveInt` at boot (same digit-only fail-closed path as TTLs /
  rate caps). Route `throttle:mcp-oauth-*` middleware is documented as a
  follow-up when authorize / token / register / revoke routes land.
- `FamilyRevokingRefreshTokenRepository` (design §8.4 / S56 / S57 / S59): atomic
  `UPDATE … WHERE revoked = false` under `lockForUpdate`; CAS miss or a
  concurrently revoked bound grant throws `invalid_grant` so League cannot
  issue after family revoke; parallel League-order race on the default DB
  (MySQL / PostgreSQL / SQLite WAL) asserts the loser persists no tokens;
  enrolled in `mutate-per-class.sh` (MSI ≥95); `FakeGrantStore` for Testbench.
- Opaque `invalid_grant` hints on refresh refusal (same League wording for
  reuse and concurrent family revoke); path details only in logs / audit
  events. Method-level `@pest-mutate-ignore` removed from the repository.

- Passport boot (design §5.6): `Passport::ignoreRoutes()` and device grant off
  in `register()` (S4 / S19); access, refresh and auth-code TTLs from raw
  `mcp-oauth.*_ttl_*` env strings in `boot()`, fail-closed on non-digit /
  signed / float / scientific / out-of-range values with documented maxima
  (access ≤1440 min, refresh ≤365 d, auth code ≤10 min).
- Passport scopes (design §5.6): `tokensCan` from `McpOAuthServer::scopeDescriptions()`
  and `defaultScopes([mcp:use])`; ClientCredentialsGrant disabled so Passport’s
  hard-coded `*` scope cannot be issued for MCP.
- `McpBearerTokenResponse` (S21): token endpoint JSON includes `scope` via
  `Passport::useAuthorizationServerResponseType`.
- Rate limiters `mcp-oauth-{register,authorize,token,revoke}` (design §5.6):
  per-IP via `ClientThrottleKey`, per-client when `client_id` / Basic auth is
  present (DCR is IP-only), 429 with `Retry-After`, fail-closed caps ≤10000/min.

- Package migrations loaded via `loadMigrationsFrom` when
  `mcp-oauth.migrations.load` is true (default; publish tag
  `mcp-oauth-migrations` kept for customise — set `load=false` after
  publishing or tables are created twice): `oauth_client_metadata` (M3:
  RFC 7591/7592 fields, CIMD cache, PAR/DPoP flags),
  `oauth_blocked_redirect_hosts` (M6: `public_id`, `match_mode`, expiry;
  `created_by` FK uses `mcp-oauth.user_model`), and `oauth_consent_records`
  (S4; Eloquent refuses update/delete). Models use explicit `$fillable` and
  mint UUID v7. CIMD runtime config defaults off. Reference schema and
  four-engine schema tests name each MUST item. JSON / `software_statement`
  size caps land in the DCR PR.

- Core runtime services: `McpOAuthServer` (three gates, Passport key usability
  including half-set env and world-readable files), `RedirectUriGuard` (League
  Uri, ASCII hosts, scheme allowlist, host block, externa bypass dataset),
  `ClientThrottleKey`, `McpOAuthReadiness`, and `MissingPassportKeysException`.
  Per-class mutation ≥95% enrolled for `McpOAuthServer` and `RedirectUriGuard`
  (with `ClientThrottleKey` and `McpOAuthReadiness`). Architecture test forbids
  `parse_url` in `src/`.

- Design §3 / §5.5 public contracts (`AdminSwitch`, `GrantStore`, …), data
  objects (`GrantRecord`, `AuthorizationDecision`, …), `RevocationReason`, and
  immutable audit events. Ids on the wire stay UUID strings (S80).

- Package scaffold: auto-discovered `McpOAuthServiceProvider`, publishable
  `config/mcp-oauth.php` (tag `mcp-oauth-config`), Pest + Testbench, Pint,
  PHPStan level max, qiick standards pack pinned to app-ui `v0.12.0`
  (`f613af9febfce3b6d7f7f41785e9845a610080c7`), CI matrix (PHP 8.3/8.4/8.5 ×
  Laravel 12/13 × lowest/stable) with `composer validate --strict`,
  `composer audit`, SHA-pinned Actions, PostgreSQL/MySQL/MariaDB/SQLite job
  shape, real-HTTP and no-dev boot cells, and README header banners.

### Documentation

- Dependency register `docs/dependencies.md`: one row per runtime
  `composer.json` `require` entry with constraint rationale, usage,
  maintainer, license, known risk and an in-package exit plan.
