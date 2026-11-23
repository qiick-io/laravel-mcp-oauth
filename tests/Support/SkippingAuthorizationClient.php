<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client;
use Laravel\Passport\Scope;

/**
 * A product client model that would auto-approve every request (Passport's
 * `skipsAuthorization()` hook), to prove MCP consent is never skipped.
 */
final class SkippingAuthorizationClient extends Client
{
    protected $table = 'oauth_clients';

    /**
     * @param  array<int, Scope>  $scopes
     */
    public function skipsAuthorization(Authenticatable $user, array $scopes): bool
    {
        return true;
    }
}
