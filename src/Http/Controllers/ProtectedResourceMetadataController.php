<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * RFC 9728 protected resource metadata of the MCP endpoint (design §5.2,
 * S13, S14; standards review S6), served at the root well-known path and at
 * the one nested path of the MCP endpoint. The document is built by
 * {@see McpOAuthServer::protectedResourceMetadata()}.
 */
final class ProtectedResourceMetadataController
{
    public function __invoke(McpOAuthServer $mcpOAuthServer): JsonResponse
    {
        return new JsonResponse($mcpOAuthServer->protectedResourceMetadata());
    }
}
