# Upgrading

The package is in its **`1.0.0` beta** line (`1.0.0-beta.N`). A beta may still
break the public API (`docs/public-api.md`) and change the migrations: until the
first stable release the `create_…` migrations are edited in place, so an
upgrade from one beta to the next may need a fresh database for the package's
tables (`php artisan migrate:fresh` on a development database). Every break is
recorded here before its tag. From `1.0.0` on, the API and the migrations follow
Semantic Versioning and the deprecation policy.

Products pin an exact beta (`qiick/laravel-mcp-oauth:1.0.0-beta.1`) until `1.0.0`.

## Unreleased

`qiick/laravel-outbound` is now a runtime dependency for Client ID Metadata
Documents (CIMD). Outbound's auto-discovered provider loads its webhook
migrations and schedules webhook retention by default. If the application uses
Outbound only for CIMD, add `qiick/laravel-outbound` to the root Composer
`extra.laravel.dont-discover` list before running package discovery again. CIMD
uses the Outbound library factory directly. Applications using Outbound's
webhook features should keep the provider and follow its own upgrade guide.

The `create_oauth_consent_records` migration adds the nullable JSON
`resource_scopes` column. Republish copies from an earlier beta. Products that
register extra protected resources also persist the approved map in their own
grant table, as described in [the reference schema](docs/reference-schema.md).

## 1.0.0-beta.1

The first release. A first install follows the README (*Install*):

```bash
composer require qiick/laravel-mcp-oauth:1.0.0-beta.1
php artisan vendor:publish --tag=mcp-oauth-config
php artisan vendor:publish --tag=passport-migrations
php artisan vendor:publish --tag=mcp-oauth-migrations
php artisan vendor:publish --tag=mcp-oauth-binding-stub
php artisan passport:keys
php artisan migrate
```

then bind the product adapters (`AdminSwitch`, `GrantStore`, `ConsentProvider`,
`GrantAuthorizer`, `ApiKeyDoor`, `McpCredentialBinder`, `AuditLogger`), call
`McpOAuthRoutes::register()`, and keep OAuth off until `mcp-oauth:check` is green.

### From the develop branch before the beta

A product that ran the package from `develop` before this tag takes these steps:

- The package now schedules `mcp-oauth:prune-unused-clients`,
  `mcp-oauth:purge-revoked` and `mcp-oauth:prune-auth-code-exchanges` itself.
  Remove your own `Schedule::command('mcp-oauth:…')` lines, or keep them and set
  `MCP_OAUTH_RETENTION_SCHEDULE=false`: with both, each job is scheduled twice,
  and `onOneServer()` does not merge two schedule entries. Run
  `php artisan config:cache` again after setting the variable: a config cache
  built before this release has no `retention.schedule` key, so the package
  schedule stays on. A value that is not a boolean (`flase`) now stops the boot
  with an error naming `retention.schedule`. Republish the config
  (`--tag=mcp-oauth-config`) to see the key; without it the default (on)
  applies. On more than one server, the single-server lock needs a cache store
  every server shares (database, Redis, Memcached, DynamoDB).
- Every event class now ends with `Event` (fleet convention F5); update each
  listener, `Event::fake()` and `Event::assert*()` call:

  | Before | After |
  | --- | --- |
  | `McpClientBlocked` | `McpClientBlockedEvent` |
  | `McpClientRegistered` | `McpClientRegisteredEvent` |
  | `McpConsentApproved` | `McpConsentApprovedEvent` |
  | `McpConsentDenied` | `McpConsentDeniedEvent` |
  | `McpGrantRevoked` | `McpGrantRevokedEvent` |
  | `McpOAuthDisabled` | `McpOAuthDisabledEvent` |
  | `McpOAuthEnabled` | `McpOAuthEnabledEvent` |
  | `McpPassportKeysMissing` | `McpPassportKeysFoundMissingEvent` |
  | `McpRedirectHostBlocked` | `McpRedirectHostBlockedEvent` |
  | `McpRedirectHostUnblocked` | `McpRedirectHostUnblockedEvent` |
  | `McpRefreshTokenReused` | `McpRefreshTokenReusedEvent` |
  | `McpRevokedRecordsPurged` | `McpRevokedRecordsPurgedEvent` |
  | `McpTokenRevoked` | `McpTokenRevokedEvent` |
  | `McpUnusedClientsPruned` | `McpUnusedClientsPrunedEvent` |

  The namespace (`Qiick\McpOAuth\Events`), the constructor arguments and the
  audit entry names (`oauth_consent_approved`, …) do not change.
- `GrantRecord` has three optional fields, `revokedAt`, `revocationReason` and
  `metadata`: a `GrantStore` should fill the first two for revoked grants.
  `RevocationReason` gained `Security`: a `match` over it needs a default arm.
- `McpOAuthServer::SUPPORTED_GRANT_TYPES` and `SUPPORTED_CODE_CHALLENGE_METHODS`
  are now the static methods `supportedGrantTypes()` and
  `supportedCodeChallengeMethods()`, and `RegisterClientController::MAX_BODY_BYTES`
  is gone (the limit is still 65 536 bytes).
- If you already ran the blocked redirect hosts migration on PostgreSQL or
  SQLite, add the index in place:

  ```sql
  CREATE INDEX IF NOT EXISTS oauth_blocked_redirect_hosts_created_by_index
      ON oauth_blocked_redirect_hosts (created_by);
  ```

  MySQL and MariaDB already index the foreign key.
- `GrantStore` has a new method, `purgeRevokedBefore(\DateTimeImmutable $cutoff): int`:
  delete the grants revoked before the cutoff and return how many went. The
  package schedules `mcp-oauth:purge-revoked` daily and
  `mcp-oauth:prune-unused-clients` hourly itself (see the first entry above).
- Clients registered via DCR before `oauth_client_metadata` existed have no
  metadata row and are refused at authorize and token; they register again.
- `oauth_client_metadata` has a new column, `first_authorized_at`, added to its
  `create_` migration: until the first stable release the migrations are
  edited in place, so run `migrate:fresh` (and re-seed) on any database that
  already ran them. Without the column, approving a client fails with an SQL
  error.
- The consent and authorization-code exchange `create_` migrations also
  changed for erasure. Re-publish any customized copies and carry forward the
  nullable consent columns and the indexed `oauth_auth_code_exchanges.user_identifier`
  column before rebuilding a pre-release development or test database.
