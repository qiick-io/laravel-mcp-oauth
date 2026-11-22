<?php

declare(strict_types=1);

/*
 * qiick/laravel-mcp-oauth configuration.
 *
 * Defaults match the binding design (projects/qiick/packages/laravel-mcp-oauth-design.md).
 * Boot-time validation of ranges and required keys lands with the feature PRs
 * that enforce the three gates.
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

    'access_token_ttl_minutes' => (int) env('MCP_OAUTH_ACCESS_TOKEN_TTL_MINUTES', 60),

    'refresh_token_ttl_days' => (int) env('MCP_OAUTH_REFRESH_TOKEN_TTL_DAYS', 30),

    'registrations_per_minute' => (int) env('MCP_OAUTH_REGISTRATIONS_PER_MINUTE', 10),

    'registrations_global_cap' => (int) env('MCP_OAUTH_REGISTRATIONS_GLOBAL_CAP', 10000),

    'unused_client_retention_hours' => (int) env('MCP_OAUTH_UNUSED_CLIENT_RETENTION_HOURS', 24),

    'token_requests_per_minute' => (int) env('MCP_OAUTH_TOKEN_REQUESTS_PER_MINUTE', 60),

    'mcp_auth_failures_per_minute' => (int) env('MCP_OAUTH_MCP_AUTH_FAILURES_PER_MINUTE', 20),

    'host_block_chunk_size' => 100,

    /*
     * Column on oauth_access_tokens holding GrantStore::bindingKey().
     */
    'grant_binding_column' => 'api_key_id',

    /*
     * User model for created_by on blocked hosts. Null falls back to
     * config('auth.providers.users.model') at runtime.
     */
    'user_model' => null,

];
