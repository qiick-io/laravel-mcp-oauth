# Upgrading

This package is **pre-release** (`0.x`). Breaking changes are allowed between
minor versions while the major is `0`, and each break is recorded here before a
tagged release.

There are no published versions yet. When `0.1.0` ships, first-install steps and
any follow-on breaks will land in this file.

Products must adopt with an exact `0.x` version constraint until `1.0.0`.

## Unreleased

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
  delete the grants revoked before the cutoff and return how many went. Then
  schedule `mcp-oauth:purge-revoked` daily and `mcp-oauth:prune-unused-clients`
  hourly (see the README).
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
