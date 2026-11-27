<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * RFC 9728 metadata for MCP and each registered product resource. The
 * resolved route carries the additional identifier, so a request cannot
 * choose another resource through the query or its Host header.
 *
 * @internal
 */
final class ProtectedResourceMetadataController
{
    public function __invoke(McpOAuthServer $mcpOAuthServer, ?string $resourceIdentifier = null): JsonResponse
    {
        $resource = $resourceIdentifier === null ? null : $mcpOAuthServer->registeredResources()[$resourceIdentifier] ?? abort(404);

        return new JsonResponse($mcpOAuthServer->protectedResourceMetadata($resource));
    }
}
