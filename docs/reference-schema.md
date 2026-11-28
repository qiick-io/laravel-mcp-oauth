# Reference schema

Column types, indexes and FK actions for the package-owned tables the provider
loads via `loadMigrationsFrom` (publish tag `mcp-oauth-migrations` remains for
apps that customise them), and for the product-owned grant binding columns on
`oauth_access_tokens`. Verified on SQLite, PostgreSQL, MySQL and MariaDB.
Binding source: standards completeness review §2 (2026-11-22) and
[[2026-11-22 Standard names in base packages]].

Core migrations are auto-loaded when `mcp-oauth.migrations.load` is true
(default). **If you publish the migrations while `load` is still true,
`migrate` creates each table twice** (once from the package path, once from
`database/migrations`). After `vendor:publish --tag=mcp-oauth-migrations`, set
`mcp-oauth.migrations.load` to `false` (or `MCP_OAUTH_LOAD_MIGRATIONS=false`)
so only the app-owned copies run. Optional/future tables (PAR, DPoP) stay
publish-only. Edited in place until `1.0.0`. Each table has its own `create_`
file so a product that already has `oauth_blocked_redirect_hosts` (externa) can
publish and customise only what it needs. Passport’s tables are never altered;
a schema test scrapes Passport 13 migration `Schema::create` names (plus the
reserved `oauth_personal_access_clients`) and asserts no package
`Schema::create` / `Schema::table` touches them.

`oauth_blocked_redirect_hosts.created_by` references the table of
`config('mcp-oauth.user_model')`, falling back to
`config('auth.providers.users.model')` (default `users`).

UTC is assumed (`app.timezone`). Past-event stamps use `timestamp`; future
dates (`expires_at`, `retention_until`, `client_secret_expires_at`,
`metadata_document_expires_at`, `registration_access_token_expires_at`) use
`dateTime`.

## `oauth_client_metadata` (package, MUST / M3)

One row per Passport client. UUID v7 `id` (model). `token_endpoint_auth_method`
is nullable with **no** database default (registration writes the value).

| Column | Type | Null | Default | Index |
| --- | --- | --- | --- | --- |
| `id` | uuid | no | UUID v7 | PK |
| `client_id` | uuid | no | — | unique |
| `registration_source` | string(16) | no | — | index |
| `spec_revision` | string(16) | yes | null | — |
| `application_type` | string(16) | yes | null | — |
| `client_uri`, `logo_uri`, `tos_uri`, `policy_uri` | string(2048) | yes | null | — |
| `contacts` | json | yes | null | — |
| `software_id`, `software_version` | string | yes | null | — |
| `software_statement` | text | yes | null | — |
| `token_endpoint_auth_method` | string(64) | yes | **none** | — |
| `jwks_uri` | string(2048) | yes | null | — |
| `jwks` | json | yes | null | — |
| `client_id_issued_at` | timestamp | yes | null | — |
| `first_authorized_at` | timestamp | yes | null | — (set at the first approval; keeps the client out of the unused-client prune after its grant is purged) |
| `client_secret_expires_at` | dateTime | yes | null | — |
| `registration_access_token_hash` | char(64) | yes | null | unique |
| `registration_access_token_expires_at` | dateTime | yes | null | — |
| `metadata_document_url` | text | yes | null | — |
| `metadata_document_url_sha256` | char(64) | yes | null | unique |
| `metadata_document` | json | yes | null | — |
| `metadata_document_sha256` | char(64) | yes | null | — |
| `metadata_document_etag` | string | yes | null | — |
| `metadata_document_fetched_at` | timestamp | yes | null | — |
| `metadata_document_expires_at` | dateTime | yes | null | index |
| `metadata_document_status` | string(16) | yes | null | — |
| `metadata_document_error` | string(512) | yes | null | — |
| `require_pushed_authorization_requests` | boolean | no | false | — |
| `dpop_bound_access_tokens` | boolean | no | false | — |
| `has_per_install_grants` | boolean | no | false | Trusted Companion enrollment flag |
| `revoked_at` | timestamp | yes | null | index |
| `revocation_reason` | string(32) | yes | null | — |
| `retention_until` | dateTime | yes | null | index |
| `metadata` | json | yes | null | — |
| `schema_version` | unsignedSmallInteger | no | 1 | — |
| `created_at` / `updated_at` | timestamps | yes | — | — |

## `oauth_blocked_redirect_hosts` (package, MUST / M6)

| Column | Type | Null | Default | Index |
| --- | --- | --- | --- | --- |
| `id` | bigIncrements | no | — | PK (internal) |
| `public_id` | uuid | no | UUID v7 | unique (wire) |
| `host` | string | no | — | unique (ASCII) |
| `host_original` | string(1024) | yes | null | — |
| `match_mode` | string(24) | no | `host_and_subdomains` | — (`exact` blocks the host only; any other value also blocks subdomains) |
| `reason` | string(512) | yes | null | — |
| `expires_at` | dateTime | yes | null | index |
| `metadata` | json | yes | null | — |
| `schema_version` | unsignedSmallInteger | no | 1 | — |
| `created_by` | foreignId → user model table | yes | null | FK via `mcp-oauth.user_model`, null on delete |
| `created_at` / `updated_at` | timestamps | yes | — | — |

## `oauth_consent_records` (package, SHOULD for 1.0 / S4)

Append-only for normal application writes. Fleet erasure scrubs identifying
columns in place, and the retention job removes expired evidence. There is
no `updated_at`.

| Column | Type | Null | Default | Index |
| --- | --- | --- | --- | --- |
| `id` | uuid | no | UUID v7 | PK |
| `client_id` | uuid | no | — | index |
| `user_identifier` | string(64) | yes | null | index |
| `grant_id` | uuid | yes | null | index |
| `decision` | string(16) | no | — | — |
| `redirect_uri` | text | yes | null | — |
| `redirect_host` | string | yes | null | — |
| `resource` | string(512) | yes | null | — |
| `resource_scopes` | json | yes | null | Complete resource-to-scope map shown at approval or denial for a registered resource |
| `requested_scopes` | json | no | — | — |
| `granted_scopes` | json | yes | null | — |
| `role` | string | yes | null | — |
| `resources` | json | yes | null | — |
| `all_resources` | boolean | no | false | — |
| `attributes` | json | yes | null | — |
| `consent_version` | string(32) | yes | null | — |
| `locale` | string(16) | yes | null | — |
| `ip_address` | string(45) | yes | null | — |
| `user_agent` | string(512) | yes | null | — |
| `correlation_id` | string(64) | yes | null | — |
| `retention_until` | dateTime | yes | null | index |
| `metadata` | json | yes | null | — |
| `schema_version` | unsignedSmallInteger | no | 1 | — |
| `created_at` | timestamp | no | current | index |

## `oauth_auth_code_exchanges` (package, MUST / RFC 9700 §4.5)

The grant an authorization code was issued for (per-install clients) or
consumed under (other clients). An installed client's pending row keeps the
code's expiry until consumption. A consumed code presented again (before or
after it expired) revokes that grant and every token bound to it. Passport does not link tokens
to their code and its tables are never altered, hence this side table.

**M7 exception:** no UUID `id`. The row is keyed by Passport's code id; it is
technical, never leaves the database and never appears on the wire, so a
public id would identify nothing anyone asks for. It still carries `metadata`
and `schema_version` like every package table.

| Column | Type | Null | Default | Index |
| --- | --- | --- | --- | --- |
| `auth_code_id` | string(100) | no | — | PK (Passport `oauth_auth_codes.id`) |
| `grant_id` | uuid | no | — | index |
| `expires_at` | dateTime | yes | null | index, pending code expiry, cleared at consumption |
| `user_identifier` | string(64) | yes | null | index, preserves erasure lookup after the original code expires |
| `metadata` | json | yes | null | — |
| `schema_version` | unsignedSmallInteger | no | 1 | — |
| `created_at` | timestamp | no | current | index (future prune after the refresh-token TTL) |

## Grant binding (product stub, tag `mcp-oauth-binding-stub`)

Added to Passport’s `oauth_access_tokens` (product-owned; not in this package’s
migrations):

| Column | Type | Notes |
| --- | --- | --- |
| `{grant_binding_column}` (default `api_key_id`) | `foreignId` or `foreignUuid` | Nullable, indexed, cascade on grant delete |
| `audience` | string(512), nullable | Exact resource identifier at mint time |

Products that register additional protected resources also store
`resource_scopes` (JSON) on their grant table. The map copies the approved
canonical resource identifiers and their wire scopes. Return it in
`GrantRecord::resourceScopes` on every read and preserve the pairs for the
lifetime of the grant. A grant for the default MCP resource may omit the map.

Per-install stores persist the selected `organisation_id` (nullable UUID),
the `install_id` (UUIDv4), the `companion_jkt` (43 base64url characters) and
the UTC consent time. They keep one active grant per
`(client_id, user_identifier, organisation_id, install_id)`, including the
single-tenant case where the organisation is null.

## Passport base tables

Publish Passport’s own `passport-migrations` tag unchanged
(`oauth_auth_codes`, `oauth_access_tokens`, `oauth_refresh_tokens`,
`oauth_clients`). Device codes may be omitted (device grant off).
