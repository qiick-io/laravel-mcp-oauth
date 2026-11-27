<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Qiick\McpOAuth\Actions\PruneUnusedClientsAction;
use Symfony\Component\HttpFoundation\Response;

/**
 * `POST mcp-oauth-clients/prune-unused` (design §5.2): an admin runs the
 * unused-client prune now instead of waiting for the hourly schedule. Same
 * rules as `mcp-oauth:prune-unused-clients`. Answers the count to a JSON
 * call and redirects back for a form or Inertia post.
 *
 * @internal
 */
final class PruneUnusedClientsController
{
    public function __invoke(Request $request, PruneUnusedClientsAction $pruneUnusedClients): Response
    {
        $prunedClientCount = $pruneUnusedClients->execute(false)->clientCount;

        return $request->expectsJson() ? new JsonResponse(['prunedClientCount' => $prunedClientCount]) : back();
    }
}
