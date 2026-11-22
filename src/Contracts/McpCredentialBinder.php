<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Http\Request;
use Qiick\McpOAuth\Data\GrantRecord;

/**
 * Binds the resolved credential to the request identically for both doors.
 *
 * @api
 */
interface McpCredentialBinder
{
    public function bindApiKey(Request $request, object $apiKey): void;

    public function bindGrant(Request $request, GrantRecord $grant): void;
}
