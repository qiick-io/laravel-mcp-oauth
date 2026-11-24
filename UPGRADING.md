# Upgrading

This package is **pre-release** (`0.x`). Breaking changes are allowed between
minor versions while the major is `0`, and each break is recorded here before a
tagged release.

There are no published versions yet. When `0.1.0` ships, first-install steps and
any follow-on breaks will land in this file.

Products must adopt with an exact `0.x` version constraint until `1.0.0`.

## Unreleased

- `GrantStore` has a new method, `purgeRevokedBefore(\DateTimeImmutable $cutoff): int`:
  delete the grants revoked before the cutoff and return how many went. Then
  schedule `mcp-oauth:purge-revoked` daily and `mcp-oauth:prune-unused-clients`
  hourly (see the README).
- Clients registered via DCR before `oauth_client_metadata` existed have no
  metadata row and are refused at authorize and token; they register again.
