<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Passport's user identifier ↔ the product's user.
 *
 * @api
 */
interface OAuthUserResolver
{
    public function find(string $identifier): ?Authenticatable;

    public function identifier(Authenticatable $user): string;
}
