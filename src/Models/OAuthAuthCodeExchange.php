<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Models;

use Illuminate\Database\Eloquent\Model;
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
    protected $fillable = ['auth_code_id', 'grant_id'];
}
