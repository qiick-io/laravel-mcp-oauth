# Changelog

All notable changes to **laravel-mcp-oauth** (`qiick/laravel-mcp-oauth`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `RedirectUriGuard` refuses hostless `http(s)` redirect URIs (`https:///…`,
  `https:/…`, …) and canonicalises IPv6 / unmaps `::ffff:` so alternate
  spellings hit the same block; non-dotted-decimal IPv4 forms are refused.
- `McpOAuthServer`: a throwing `AdminSwitch` counts as OFF (S11); `isReady`
  requires an absolute `app.url`; `mcp_path` trailing slashes normalised;
  resource host comparison is case-insensitive.
- `ClientThrottleKey` excludes `::/127` from IPv4-compatible unmapping and
  unmaps `::ffff:0:a.b.c.d` plus `64:ff9b:1::/48`.

### Added

- Package migrations (publish tag `mcp-oauth-migrations`, never auto-loaded):
  `oauth_client_metadata` (M3: RFC 7591/7592 fields, CIMD cache, PAR/DPoP
  flags), `oauth_blocked_redirect_hosts` (M6: `public_id`, `match_mode`,
  expiry), and `oauth_consent_records` (S4). Eloquent models mint UUID v7.
  CIMD runtime config defaults off (`mcp-oauth.cimd.enabled`). Reference
  schema and four-engine schema tests name each MUST item.

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
