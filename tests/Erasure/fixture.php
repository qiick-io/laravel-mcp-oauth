<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Qiick\McpOAuth\Erasure\McpOAuthEraser;
use Qiick\McpOAuth\Tests\Support\TestUser;
use Qiick\Standards\Erasure\Support\ErasureFixture;
use Qiick\Standards\Erasure\Support\ErasurePerson;

/**
 * Inventory of the MCP OAuth tables and the Passport tables they use.
 * Client registrations describe shared applications. Session data belongs to
 * the product. The only Laravel cache writes are shared per-IP or per-client
 * rate-limit counters with a 60-second TTL, independent of the signed-in user.
 */
return new class implements ErasureFixture
{
    public function packageName(): string
    {
        return 'qiick/laravel-mcp-oauth';
    }

    public function eraserClass(): string
    {
        return McpOAuthEraser::class;
    }

    public function connectionName(): ?string
    {
        return null;
    }

    public function tables(): array
    {
        return [
            'oauth_client_metadata' => array_fill_keys([
                'id', 'client_id', 'registration_source', 'spec_revision', 'application_type', 'client_uri',
                'logo_uri', 'tos_uri', 'policy_uri', 'contacts', 'software_id', 'software_version', 'software_statement',
                'token_endpoint_auth_method', 'jwks_uri', 'jwks', 'client_id_issued_at', 'first_authorized_at',
                'client_secret_expires_at', 'registration_access_token_hash', 'registration_access_token_expires_at',
                'metadata_document_url', 'metadata_document_url_sha256', 'metadata_document', 'metadata_document_sha256',
                'metadata_document_etag', 'metadata_document_fetched_at', 'metadata_document_expires_at',
                'metadata_document_status', 'metadata_document_error', 'require_pushed_authorization_requests',
                'dpop_bound_access_tokens', 'has_per_install_grants', 'revoked_at', 'revocation_reason', 'retention_until', 'metadata',
                'schema_version', 'created_at', 'updated_at',
            ], 'other'),
            'oauth_clients' => array_fill_keys([
                'id', 'owner_type', 'owner_id', 'name', 'secret', 'provider', 'redirect_uris', 'grant_types',
                'revoked', 'created_at', 'updated_at',
            ], 'other'),
            'oauth_consent_records' => [
                ...array_fill_keys(['id', 'client_id', 'decision', 'all_resources', 'retention_until', 'schema_version', 'created_at'], 'other'),
                ...array_fill_keys([
                    'user_identifier', 'grant_id', 'redirect_uri', 'redirect_host', 'resource', 'resource_scopes', 'requested_scopes',
                    'granted_scopes', 'role', 'resources', 'attributes', 'consent_version', 'locale', 'ip_address',
                    'user_agent', 'correlation_id', 'metadata',
                ], 'personal'),
            ],
            'oauth_blocked_redirect_hosts' => [
                ...array_fill_keys(['id', 'public_id', 'host', 'host_original', 'match_mode', 'expires_at', 'schema_version', 'created_at', 'updated_at'], 'other'),
                ...array_fill_keys(['created_by', 'reason', 'metadata'], 'personal'),
            ],
            'oauth_auth_codes' => [
                ...array_fill_keys(['client_id', 'revoked', 'expires_at'], 'other'),
                ...array_fill_keys(['id', 'user_id', 'scopes'], 'personal'),
            ],
            'oauth_auth_code_exchanges' => [
                ...array_fill_keys(['schema_version', 'created_at', 'expires_at'], 'other'),
                ...array_fill_keys(['auth_code_id', 'grant_id', 'user_identifier', 'metadata'], 'personal'),
            ],
            'oauth_access_tokens' => [
                ...array_fill_keys(['client_id', 'revoked', 'created_at', 'updated_at', 'expires_at'], 'other'),
                ...array_fill_keys(['id', 'user_id', 'name', 'scopes', 'api_key_id', 'audience'], 'personal'),
            ],
            'oauth_refresh_tokens' => [
                ...array_fill_keys(['revoked', 'expires_at'], 'other'),
                ...array_fill_keys(['id', 'access_token_id'], 'personal'),
            ],
        ];
    }

    public function makePerson(): ErasurePerson
    {
        $userId = ((int) TestUser::query()->max('id')) + 1_000_001;
        TestUser::query()->create(['id' => $userId]);

        return ErasurePerson::fresh((string) $userId);
    }

    public function seed(ErasurePerson $person, ?string $organisationId): void
    {
        [$email, $username, $displayName] = $person->identifiers;
        [$ipAddress, $userAgent] = $person->otherPersonalValues;
        $grantId = $person->publicIds[1];
        $clientId = (string) Str::uuid();
        $authCodeId = Str::random(80);
        $accessTokenId = $person->userPublicId.Str::random(44);
        $personalScopes = json_encode([$username], JSON_THROW_ON_ERROR);

        DB::table('oauth_clients')->insert([
            'id' => $clientId,
            'name' => 'Shared client',
            'redirect_uris' => '["https://client.example.test/callback"]',
            'grant_types' => '["authorization_code","refresh_token"]',
            'revoked' => false,
        ]);
        DB::table('oauth_client_metadata')->insert([
            'id' => (string) Str::uuid(),
            'client_id' => $clientId,
            'registration_source' => 'admin',
        ]);
        DB::table('oauth_consent_records')->insert([
            'id' => (string) Str::uuid(),
            'client_id' => $clientId,
            'user_identifier' => $person->userId,
            'grant_id' => $grantId,
            'decision' => 'approved',
            'redirect_uri' => 'https://client.example.test/callback?login_hint='.rawurlencode($email),
            'redirect_host' => "{$username}.example.test",
            'resource' => "https://example.test/{$username}",
            'resource_scopes' => json_encode(["https://example.test/{$username}" => 'mcp:use'], JSON_THROW_ON_ERROR),
            'requested_scopes' => $personalScopes,
            'granted_scopes' => $personalScopes,
            'role' => $username,
            'resources' => $personalScopes,
            'all_resources' => true,
            'attributes' => json_encode(['name' => $displayName], JSON_THROW_ON_ERROR),
            'consent_version' => Str::random(10),
            'locale' => 'en-GB',
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'correlation_id' => (string) Str::uuid(),
            'metadata' => json_encode(['email' => $email], JSON_THROW_ON_ERROR),
        ]);
        DB::table('oauth_blocked_redirect_hosts')->insert([
            'public_id' => (string) Str::uuid(),
            'host' => Str::lower(Str::random(10)).'.example.test',
            'created_by' => $person->userId,
            'reason' => "Reported by {$displayName}",
            'metadata' => json_encode(['email' => $email], JSON_THROW_ON_ERROR),
        ]);
        DB::table('oauth_auth_codes')->insert([
            'id' => $authCodeId,
            'user_id' => $person->userId,
            'client_id' => $clientId,
            'scopes' => $personalScopes,
            'revoked' => true,
        ]);
        DB::table('oauth_auth_code_exchanges')->insert([
            'auth_code_id' => $authCodeId,
            'grant_id' => $grantId,
            'user_identifier' => $person->userId,
            'metadata' => json_encode(['email' => $email], JSON_THROW_ON_ERROR),
        ]);
        DB::table('oauth_access_tokens')->insert([
            'id' => $accessTokenId,
            'user_id' => $person->userId,
            'client_id' => $clientId,
            'name' => $displayName,
            'scopes' => $personalScopes,
            'revoked' => false,
            'api_key_id' => $grantId,
            'audience' => "https://example.test/{$username}",
        ]);
        DB::table('oauth_refresh_tokens')->insert([
            'id' => Str::random(80),
            'access_token_id' => $accessTokenId,
            'revoked' => false,
        ]);
    }

    public function retainedCleartextColumns(): array
    {
        return [];
    }

    public function diskPaths(ErasurePerson $person): array
    {
        return [];
    }

    public function additionalConnections(): array
    {
        return [];
    }

    public function supportsOrganisationScope(): bool
    {
        return false;
    }

    public function organisationScopedTables(): array
    {
        return [];
    }

    public function cacheKeys(ErasurePerson $person): array
    {
        return [];
    }

    public function call(Closure $erase): object
    {
        return $erase();
    }
};
