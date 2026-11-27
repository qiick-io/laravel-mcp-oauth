<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * Eloquent row for oauth_blocked_redirect_hosts. Internal bigint id; public_id
 * is the UUID v7 on the wire (M6 / M7 / M10).
 *
 * @property string|null $public_id
 * @property string $host
 * @property string $match_mode
 *
 * @internal
 */
final class OAuthBlockedRedirectHost extends Model
{
    protected $table = 'oauth_blocked_redirect_hosts';

    /** Blocks the host only; the default `host_and_subdomains` also blocks every subdomain. */
    public const string MATCH_MODE_EXACT = 'exact';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'public_id',
        'host',
        'host_original',
        'match_mode',
        'reason',
        'expires_at',
        'metadata',
        'schema_version',
        'created_by',
    ];

    protected static function booted(): void
    {
        self::creating(function (self $host): void {
            if ($host->getAttribute('public_id') === null || $host->getAttribute('public_id') === '') {
                $host->setAttribute('public_id', (string) Str::uuid7());
            }
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'metadata' => 'array',
            'schema_version' => 'integer',
        ];
    }

    public function getRouteKeyName(): string
    {
        return 'public_id';
    }
}
