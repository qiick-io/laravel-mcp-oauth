<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * RFC 9728 protected resource metadata of the MCP endpoint (design §5.2,
 * S13, S14; standards review S6), served at the root well-known path and at
 * the one nested path of the MCP endpoint. The resource and the
 * authorization server are this server's issuer (APP_URL); Bearer tokens are
 * accepted in the Authorization header only.
 */
final class ProtectedResourceMetadataController
{
    public function __invoke(McpOAuthServer $mcpOAuthServer): JsonResponse
    {
        return new JsonResponse([
            'resource' => $mcpOAuthServer->resourceIdentifier(),
            'authorization_servers' => [$mcpOAuthServer->issuer()],
            'scopes_supported' => [McpOAuthServer::WIRE_SCOPE],
            'bearer_methods_supported' => ['header'],
        ]);
    }
}
