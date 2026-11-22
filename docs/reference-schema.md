# Reference schema

Column types, indexes and FK actions for the package-owned tables published
under tag `mcp-oauth-migrations`, and for the product-owned grant binding
columns on `oauth_access_tokens`. Verified on SQLite, PostgreSQL, MySQL and
MariaDB. Binding source: standards completeness review §2 (2026-11-22) and
[[2026-11-22 Standard names in base packages]].

Migrations are published, never auto-loaded, and edited in place until `1.0.0`.
Each table has its own `create_` file so a product that already has
`oauth_blocked_redirect_hosts` (externa) publishes only the files it lacks.
Passport’s tables are never altered; no package table collides with
`oauth_auth_codes`, `oauth_access_tokens`, `oauth_refresh_tokens`,
`oauth_clients`, `oauth_device_codes` or reserved `oauth_personal_access_clients`.

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
| `match_mode` | string(24) | no | `host_and_subdomains` | — |
| `reason` | string(512) | yes | null | — |
| `expires_at` | dateTime | yes | null | index |
| `metadata` | json | yes | null | — |
| `schema_version` | unsignedSmallInteger | no | 1 | — |
| `created_by` | foreignId → users | yes | null | FK, null on delete |
| `created_at` / `updated_at` | timestamps | yes | — | — |

## `oauth_consent_records` (package, SHOULD for 1.0 / S4)

Append-only: no `updated_at`.

| Column | Type | Null | Default | Index |
| --- | --- | --- | --- | --- |
| `id` | uuid | no | UUID v7 | PK |
| `client_id` | uuid | no | — | index |
| `user_identifier` | string(64) | no | — | index |
| `grant_id` | uuid | yes | null | index |
| `decision` | string(16) | no | — | — |
| `redirect_uri` | text | no | — | — |
| `redirect_host` | string | no | — | — |
| `resource` | string(512) | yes | null | — |
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

## Grant binding (product stub, tag `mcp-oauth-binding-stub`)

Added to Passport’s `oauth_access_tokens` (product-owned; not in this package’s
migrations):

| Column | Type | Notes |
| --- | --- | --- |
| `{grant_binding_column}` (default `api_key_id`) | `foreignId` or `foreignUuid` | Nullable, indexed, cascade on grant delete |
| `audience` | string(512), nullable | Exact resource identifier at mint time |

## Passport base tables

Publish Passport’s own `passport-migrations` tag unchanged
(`oauth_auth_codes`, `oauth_access_tokens`, `oauth_refresh_tokens`,
`oauth_clients`). Device codes may be omitted (device grant off).
