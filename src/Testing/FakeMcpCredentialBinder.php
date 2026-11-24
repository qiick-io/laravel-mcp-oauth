<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Illuminate\Http\Request;
use Qiick\McpOAuth\Contracts\McpCredentialBinder;
use Qiick\McpOAuth\Data\GrantRecord;

/**
 * In-memory {@see McpCredentialBinder}: records what each door bound and
 * puts it on the request as `mcp_credential`.
 *
 * @api
 */
final class FakeMcpCredentialBinder implements McpCredentialBinder
{
    /** @var list<object> */
    public array $boundApiKeys = [];

    /** @var list<GrantRecord> */
    public array $boundGrants = [];

    public function bindApiKey(Request $request, object $apiKey): void
    {
        $this->boundApiKeys[] = $apiKey;
        $request->attributes->set('mcp_credential', $apiKey);
    }

    public function bindGrant(Request $request, GrantRecord $grant): void
    {
        $this->boundGrants[] = $grant;
        $request->attributes->set('mcp_credential', $grant);
    }
}
