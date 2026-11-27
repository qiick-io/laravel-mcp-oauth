<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Http\Request;
use Qiick\McpOAuth\Data\AuthorizationDecision;
use Qiick\McpOAuth\Data\GrantRecord;

/**
 * Use-time entitlement for an OAuth grant.
 *
 * @api
 */
interface GrantAuthorizer
{
    public function authorize(Request $request, GrantRecord $grant): AuthorizationDecision;
}
