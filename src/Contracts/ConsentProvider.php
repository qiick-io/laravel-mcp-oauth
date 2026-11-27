<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Qiick\McpOAuth\Data\ClientInfo;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\ConsentOptions;

/**
 * What the consent screen offers, and whether an approval stays within it.
 *
 * @api
 */
interface ConsentProvider
{
    public function options(Request $request, Authenticatable $user, ClientInfo $client): ConsentOptions;

    /**
     * Throws when the posted choices leave the offered set or the user may not
     * approve at all (422 field errors, or 403).
     */
    public function validate(Request $request, Authenticatable $user, ConsentDecision $decision): void;
}
