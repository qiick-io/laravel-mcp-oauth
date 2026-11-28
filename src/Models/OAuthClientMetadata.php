<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Traits\UsesPassportConnectionTrait;

/**
 * Eloquent row for oauth_client_metadata (RFC 7591 side table). UUID v7 primary
 * key via {@see HasUuids}; Passport's oauth_clients is never altered.
 *
 * @internal
 */
final class OAuthClientMetadata extends Model
{
    use HasUuids;
    use UsesPassportConnectionTrait;

    protected $table = 'oauth_client_metadata';

    // PCOV has no line coverage for a declared property's initializer.
    // @pest-mutate-ignore: RemoveArrayItem
    /**
     * @var list<string>
     */
    protected $fillable = [
        'client_id',
        'registration_source',
        'spec_revision',
        'application_type',
        'client_uri',
        'logo_uri',
        'tos_uri',
        'policy_uri',
        'contacts',
        'software_id',
        'software_version',
        'software_statement',
        'token_endpoint_auth_method',
        'jwks_uri',
        'jwks',
        'client_id_issued_at',
        'first_authorized_at',
        'client_secret_expires_at',
        'registration_access_token_hash',
        'registration_access_token_expires_at',
        'metadata_document_url',
        'metadata_document_url_sha256',
        'metadata_document',
        'metadata_document_sha256',
        'metadata_document_etag',
        'metadata_document_fetched_at',
        'metadata_document_expires_at',
        'metadata_document_status',
        'metadata_document_error',
        'require_pushed_authorization_requests',
        'dpop_bound_access_tokens',
        'has_per_install_grants',
        'revoked_at',
        'revocation_reason',
        'retention_until',
        'metadata',
        'schema_version',
    ];

    /**
     * A client the package registered (DCR writes this row). Only those reach
     * the authorize and token endpoints and get their tokens bound: a
     * product's own Passport client never becomes an unbound MCP client.
     */
    public static function isRegisteredClient(Client|string $client): bool
    {
        $clientId = $client instanceof Client ? $client->getKey() : $client;

        return self::query()->where('client_id', $clientId)->exists();
    }

    /** The flag belongs to trusted enrollment and is unavailable to DCR or fetched CIMD. */
    public static function isPerInstallClient(string $clientId): bool
    {
        return self::query()
            ->where('client_id', $clientId)
            ->where('registration_source', 'companion')
            ->where('has_per_install_grants', true)
            ->exists();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'contacts' => 'array',
            'jwks' => 'array',
            'metadata_document' => 'array',
            'metadata' => 'array',
            'client_id_issued_at' => 'datetime',
            'first_authorized_at' => 'datetime',
            'client_secret_expires_at' => 'datetime',
            'registration_access_token_expires_at' => 'datetime',
            'metadata_document_fetched_at' => 'datetime',
            'metadata_document_expires_at' => 'datetime',
            'require_pushed_authorization_requests' => 'boolean',
            'dpop_bound_access_tokens' => 'boolean',
            'has_per_install_grants' => 'boolean',
            'revoked_at' => 'datetime',
            'retention_until' => 'datetime',
            'schema_version' => 'integer',
        ];
    }
}
