<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * The grant an authorization code was consumed under, so a code presented
 * again can revoke the tokens issued with it (OneShotAuthCodeRepository).
 *
 * ponytail: rows are never pruned yet; one is needed only while a token
 * issued with the code can live (the refresh-token TTL). The prune command
 * that lands with the admin pages should delete older rows.
 *
 * @property string $auth_code_id
 * @property string $grant_id
 *
 * @internal
 */
final class OAuthAuthCodeExchange extends Model
{
    public $timestamps = false;

    public $incrementing = false;

    protected $table = 'oauth_auth_code_exchanges';

    protected $primaryKey = 'auth_code_id';

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = ['auth_code_id', 'grant_id'];

    /**
     * Passport's connection, like the code row it is written beside: consuming
     * the code and recording its grant share one transaction.
     */
    public function getConnectionName(): ?string
    {
        $passportConnection = config('passport.connection');

        return is_string($passportConnection) ? $passportConnection : null;
    }
}
