# Changelog

All notable changes to **laravel-mcp-oauth** (`qiick/laravel-mcp-oauth`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
  `oauth_auth_code_exchanges` records that grant.
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
