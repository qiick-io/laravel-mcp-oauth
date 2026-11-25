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
- `oauth_client_metadata` has a new column, `first_authorized_at`, added to its
  `create_` migration (the migrations are edited in place until the first
  stable release, so `migrate` will not add it to a database that already ran
  them). Without it, approving a client fails with an SQL error, and once a
  revoked grant is purged, `mcp-oauth:prune-unused-clients` would delete a
  client users had authorised. Either run `migrate:fresh`, or add the column
  and backfill it before scheduling the prune:

  ```php
  Schema::table('oauth_client_metadata', fn (Blueprint $table) => $table->timestamp('first_authorized_at')->nullable());

  // Every client a user ever approved: the product's grants (revoked ones
  // included), or an approval in the consent records.
  $approvedClientIds = array_merge(
      app(GrantStore::class)->everAuthorized(OAuthClientMetadata::query()->pluck('client_id')->all()),
      OAuthConsentRecord::query()->where('decision', 'approved')->distinct()->pluck('client_id')->all(),
  );
  OAuthClientMetadata::query()->whereIn('client_id', $approvedClientIds)->update(['first_authorized_at' => now()]);
  ```
