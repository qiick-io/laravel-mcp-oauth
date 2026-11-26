<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use LogicException;

/**
 * Append-only consent evidence row (S4). No updated_at; the model refuses
 * update and delete to protect the audit trail. The retention and erasure
 * operations use the query builder for their limited writes.
 *
 * @internal
 */
final class OAuthConsentRecord extends Model
{
    use HasUuids;

    public $timestamps = false;

    protected $table = 'oauth_consent_records';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'client_id',
        'user_identifier',
        'grant_id',
        'decision',
        'redirect_uri',
        'redirect_host',
        'resource',
        'requested_scopes',
        'granted_scopes',
        'role',
        'resources',
        'all_resources',
        'attributes',
        'consent_version',
        'locale',
        'ip_address',
        'user_agent',
        'correlation_id',
        'retention_until',
        'metadata',
        'schema_version',
        'created_at',
    ];

    protected static function booted(): void
    {
        self::updating(static function (): never {
            throw new LogicException('oauth_consent_records is append-only; updates are refused.');
        });

        self::deleting(static function (): never {
            throw new LogicException('oauth_consent_records is append-only; deletes are refused.');
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'requested_scopes' => 'array',
            'granted_scopes' => 'array',
            'resources' => 'array',
            'attributes' => 'array',
            'all_resources' => 'boolean',
            'retention_until' => 'datetime',
            'metadata' => 'array',
            'schema_version' => 'integer',
            'created_at' => 'datetime',
        ];
    }
}
