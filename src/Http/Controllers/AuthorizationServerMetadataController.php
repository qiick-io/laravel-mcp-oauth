<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * RFC 8414 authorization server metadata (design §5.2, S13, S15; standards
 * review M1, M2, S1). The document is built by
 * {@see McpOAuthServer::authorizationServerMetadata()}, so adopters read the
 * same members the endpoint serves.
 */
final class AuthorizationServerMetadataController
{
    public function __invoke(McpOAuthServer $mcpOAuthServer): JsonResponse
    {
        return new JsonResponse($mcpOAuthServer->authorizationServerMetadata());
    }
}
