# Upgrading

This package is **pre-release** (`0.x`). Breaking changes are allowed between
minor versions while the major is `0`, and each break is recorded here before a
tagged release.

There are no published versions yet. When `0.1.0` ships, first-install steps and
any follow-on breaks will land in this file.

Products must adopt with an exact `0.x` version constraint until `1.0.0`.

## Unreleased

- `GrantRecord` has three optional fields, `revokedAt`, `revocationReason` and
  `metadata`: a `GrantStore` should fill the first two for revoked grants.
  `RevocationReason` gained `Security`: a `match` over it needs a default arm.
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
