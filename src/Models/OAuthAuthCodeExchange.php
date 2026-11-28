<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Qiick\McpOAuth\Traits\UsesPassportConnectionTrait;

/**
 * The grant an authorization code was consumed under, so a code presented
 * again can revoke the tokens issued with it (OneShotAuthCodeRepository).
 *
 * A row is needed only while its grant is active;
 * `mcp-oauth:prune-auth-code-exchanges` deletes the others.
 *
 * @property string $auth_code_id
 * @property string $grant_id
 * @property Carbon|null $expires_at Pending codes carry their expiry. Consumed codes carry null.
 * @property array<string, mixed>|null $metadata
 * @property int $schema_version
 *
 * @internal
 */
final class OAuthAuthCodeExchange extends Model
{
    use UsesPassportConnectionTrait;

    public $timestamps = false;

    public $incrementing = false;

    protected $table = 'oauth_auth_code_exchanges';

    protected $primaryKey = 'auth_code_id';

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = ['auth_code_id', 'grant_id', 'user_identifier', 'metadata', 'expires_at'];

    /**
     * `schema_version` is an int on every engine (PostgreSQL and MySQL drivers
     * may return a numeric string).
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'metadata' => 'array',
            'expires_at' => 'datetime',
            'schema_version' => 'integer',
        ];
    }
}
