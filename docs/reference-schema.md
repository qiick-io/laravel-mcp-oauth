# Reference schema

Column types, indexes and FK actions for the package-owned
`oauth_blocked_redirect_hosts` table and for the product-owned grant binding
columns on `oauth_access_tokens`. Verified on SQLite, PostgreSQL, MySQL and
MariaDB once migrations land.

## `oauth_blocked_redirect_hosts` (package, publish tag `mcp-oauth-migrations`)

| Column | Type | Notes |
| --- | --- | --- |
| `id` | bigint / bigIncrements | |
| `host` | string, unique | Normalised ASCII (UTS #46 nontransitional STD3) |
| `created_by` | nullable FK → users | Null on user delete |
| `created_at` / `updated_at` | timestamps | |

Publish, never auto-load. Products that already have the table publish nothing.

## Grant binding (product stub, tag `mcp-oauth-binding-stub`)

Added to Passport’s `oauth_access_tokens`:

| Column | Type | Notes |
| --- | --- | --- |
| `{grant_binding_column}` (default `api_key_id`) | `foreignId` or `foreignUuid` | Nullable, indexed, cascade on grant delete |
| `audience` | string(512), nullable | Exact resource identifier at mint time |

A token missing either is refused at use time. Products pick the `foreignId` or
`foreignUuid` stub to match their grant primary key.

## Passport base tables

Publish Passport’s own `passport-migrations` tag unchanged
(`oauth_auth_codes`, `oauth_access_tokens`, `oauth_refresh_tokens`,
`oauth_clients`). Device codes may be omitted (device grant off).
