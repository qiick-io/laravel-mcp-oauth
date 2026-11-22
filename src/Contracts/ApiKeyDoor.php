<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Http\Request;

/**
 * The product's API-key door, so both doors share one selection algorithm.
 *
 * @api
 */
interface ApiKeyDoor
{
    /**
     * True when the token has the product's API-key shape (`ext_…`, `ek_…`, …).
     */
    public function isApiKeyShaped(string $bearer): bool;

    /**
     * Authenticates and authorises an API key for /mcp; throws the product's
     * 401/403.
     */
    public function authenticate(Request $request, string $bearer): object;
}
