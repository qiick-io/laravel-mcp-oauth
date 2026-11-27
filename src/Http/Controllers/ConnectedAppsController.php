<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Qiick\McpOAuth\Actions\RevokeConnectedAppAction;
use Qiick\McpOAuth\Services\ConnectedAppsService;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Connected apps for the signed-in user (design §5.2), mounted by
 * McpOAuthSettingsRoutes inside the product's auth middleware. A user only
 * ever sees and revokes their own active grants; anything else is a 404.
 * The product owns the page: the list answers JSON, and a revoke answers 204
 * to a JSON call and redirects back for a form or Inertia post.
 *
 * @internal
 */
final class ConnectedAppsController
{
    public function index(Request $request, ConnectedAppsService $connectedApps): JsonResponse
    {
        /** @var Authenticatable $user the product's `auth` middleware guarantees one */
        $user = $request->user();

        return new JsonResponse(['connectedApps' => $connectedApps->forUser($user)]);
    }

    public function destroy(Request $request, string $grantId, ConnectedAppsService $connectedApps, RevokeConnectedAppAction $revokeConnectedApp): Response
    {
        /** @var Authenticatable $user the product's `auth` middleware guarantees one */
        $user = $request->user();
        $grant = $connectedApps->activeGrantOf($user, $grantId) ?? throw new NotFoundHttpException;

        $revokeConnectedApp->execute($grant, $user);

        return $request->expectsJson() ? response()->noContent() : back();
    }
}
