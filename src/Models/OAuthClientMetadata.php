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
    protected $guarded = [];

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
