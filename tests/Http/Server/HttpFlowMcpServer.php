<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Http\Server;

use Laravel\Mcp\Server;

/**
 * The product's MCP server behind the door: one tool, so `tools/list` proves
 * a request got through and reached laravel/mcp.
 */
final class HttpFlowMcpServer extends Server
{
    protected string $name = 'HTTP flow test server';

    /**
     * @var array<int, class-string<Server\Tool>>
     */
    protected array $tools = [ListNewsTool::class];
}
