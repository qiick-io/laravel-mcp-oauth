<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * Append-only consent evidence row (S4). No updated_at; retention_until is the
 * only field written after create.
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
    protected $guarded = [];

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
