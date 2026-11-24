<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Http\Server;

use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Tool;

/**
 * The one tool of HttpFlowMcpServer.
 */
#[Description('Lists the news the grant can read.')]
final class ListNewsTool extends Tool
{
    public function handle(Request $request): Response
    {
        return Response::text('No news.');
    }
}
