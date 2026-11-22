<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent row for oauth_client_metadata (RFC 7591 side table). UUID v7 primary
 * key via {@see HasUuids}; Passport's oauth_clients is never altered.
 *
 * @internal
 */
final class OAuthClientMetadata extends Model
{
    use HasUuids;

    protected $table = 'oauth_client_metadata';

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
        'revoked_at',
        'revocation_reason',
        'retention_until',
        'metadata',
        'schema_version',
    ];

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
            'client_secret_expires_at' => 'datetime',
            'registration_access_token_expires_at' => 'datetime',
            'metadata_document_fetched_at' => 'datetime',
            'metadata_document_expires_at' => 'datetime',
            'require_pushed_authorization_requests' => 'boolean',
            'dpop_bound_access_tokens' => 'boolean',
            'revoked_at' => 'datetime',
            'retention_until' => 'datetime',
            'schema_version' => 'integer',
        ];
    }
}
