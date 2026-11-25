<?php

declare(strict_types=1);

/*
 * qiick/laravel-mcp-oauth configuration.
 *
 * Defaults match the binding design (projects/qiick/packages/laravel-mcp-oauth-design.md).
 * Every integer key is validated at boot (design §6); an invalid value fails
 * closed with a message instead of being cast or replaced.
 */

return [

    /*
     * Deployment safety gate (MCP_OAUTH_ENABLED). Default off: OAuth routes
     * answer 404 until this flag, the AdminSwitch and mcp_enabled are all true.
     */
    'enabled' => (bool) env('MCP_OAUTH_ENABLED', false),

    /*
     * Product MCP flag (gate 3). Config key string or closure bound by the
     * product. Must be set before OAuth can be switched on; null until then.
     */
    'mcp_enabled' => null,

    /*
     * Resource path appended to APP_URL for the protected-resource identifier.
     */
    'mcp_path' => 'mcp',

    /*
     * Token lifetimes. Kept as raw env strings (or missing → default string)
     * so BoundedPositiveInt can reject float / scientific / signed forms
     * before any (int) cast. Boot fails closed outside 1..MAX.
     *
     * access: 1..1440 minutes (default 60)
     * refresh: 1..365 days (default 30)
     * auth code: 1..10 minutes (default 10; Passport/league AuthCodeGrant)
     */
    'access_token_ttl_minutes' => env('MCP_OAUTH_ACCESS_TOKEN_TTL_MINUTES', '60'),

    'refresh_token_ttl_days' => env('MCP_OAUTH_REFRESH_TOKEN_TTL_DAYS', '30'),

    'auth_code_ttl_minutes' => env('MCP_OAUTH_AUTH_CODE_TTL_MINUTES', '10'),

    /*
     * Named rate limiters (design §5.6): throttle:mcp-oauth-{register,authorize,
     * token,revoke}. Per-IP via ClientThrottleKey; per-client when client_id
     * (or HTTP Basic user) is present. DCR is IP-only (no client yet). Raw
     * env strings; boot validates 1..10000. 429 responses include Retry-After.
     *
     * DCR attaches `throttle:mcp-oauth-register` via McpOAuthRoutes. Follow-up:
     * authorize / token / revoke middleware and HTTP 429 proofs on those routes.
     */
    'registrations_per_minute' => env('MCP_OAUTH_REGISTRATIONS_PER_MINUTE', '10'),

    'authorize_requests_per_minute' => env('MCP_OAUTH_AUTHORIZE_REQUESTS_PER_MINUTE', '30'),

    'authorize_requests_per_client_per_minute' => env('MCP_OAUTH_AUTHORIZE_REQUESTS_PER_CLIENT_PER_MINUTE', '20'),

    'token_requests_per_minute' => env('MCP_OAUTH_TOKEN_REQUESTS_PER_MINUTE', '60'),

    'token_requests_per_client_per_minute' => env('MCP_OAUTH_TOKEN_REQUESTS_PER_CLIENT_PER_MINUTE', '30'),

    'revoke_requests_per_minute' => env('MCP_OAUTH_REVOKE_REQUESTS_PER_MINUTE', '30'),

    'revoke_requests_per_client_per_minute' => env('MCP_OAUTH_REVOKE_REQUESTS_PER_CLIENT_PER_MINUTE', '20'),

    /*
     * RFC 7009 revocation at POST oauth/revoke, advertised as
     * `revocation_endpoint`. Anything but true (env `false`, `0`, a typo)
     * turns both off.
     */
    'revocation_enabled' => env('MCP_OAUTH_REVOCATION_ENABLED', true),

    /*
     * Integer keys below stay raw env strings like the TTLs: `(int) env()`
     * would turn `1e3` into 1000 and `abc` into 0 before boot validation
     * sees them. Boot fails closed outside 1..the documented maximum.
     */
    'registrations_global_cap' => env('MCP_OAUTH_REGISTRATIONS_GLOBAL_CAP', '10000'),

    'unused_client_retention_hours' => env('MCP_OAUTH_UNUSED_CLIENT_RETENTION_HOURS', '24'),

    /*
     * Days a revoked client or grant stays before mcp-oauth:purge-revoked.
     */
    'revoked_retention_days' => env('MCP_OAUTH_REVOKED_RETENTION_DAYS', '90'),

    /*
     * /mcp Bearer auth-failure limiter (lands with the door). Raw env string;
     * boot validates 1..10000 like the other per-minute caps (no (int) cast).
     */
    'mcp_auth_failures_per_minute' => env('MCP_OAUTH_MCP_AUTH_FAILURES_PER_MINUTE', '20'),

    'host_block_chunk_size' => 100,

    /*
     * MCP authorization spec revision pinned for new registrations (M8).
     */
    'spec_revision' => env('MCP_OAUTH_SPEC_REVISION', '2026-07-28'),

    /*
     * Client ID Metadata Documents (S2). Runtime off by default; schema cache
     * columns ship in oauth_client_metadata regardless.
     */
    'cimd' => [
        'enabled' => (bool) env('MCP_OAUTH_CIMD_ENABLED', false),
        'max_document_bytes' => env('MCP_OAUTH_CIMD_MAX_DOCUMENT_BYTES', '65536'),
        'timeout_seconds' => env('MCP_OAUTH_CIMD_TIMEOUT_SECONDS', '5'),
        'cache_min_seconds' => env('MCP_OAUTH_CIMD_CACHE_MIN_SECONDS', '60'),
        'cache_max_seconds' => env('MCP_OAUTH_CIMD_CACHE_MAX_SECONDS', '86400'),
    ],

    /*
     * Column on oauth_access_tokens holding GrantStore::bindingKey().
     */
    'grant_binding_column' => 'api_key_id',

    /*
     * User model for created_by on blocked hosts. Null falls back to
     * config('auth.providers.users.model') at runtime.
     */
    'user_model' => null,

    /*
     * When true (default), the provider loadMigrationsFrom the core side
     * tables. Set false when the app publishes and owns the migration files.
     */
    'migrations' => [
        'load' => (bool) env('MCP_OAUTH_LOAD_MIGRATIONS', true),
    ],

];
