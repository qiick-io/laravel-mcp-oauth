<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Validator as ValidatorInstance;
use InvalidArgumentException;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Actions\BlockClientAction;
use Qiick\McpOAuth\Actions\BlockRedirectHostAction;
use Qiick\McpOAuth\Actions\BulkBlockClientsAction;
use Qiick\McpOAuth\Actions\UnblockRedirectHostAction;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\RedirectUriGuard;
use Qiick\McpOAuth\Services\ClientAdminService;
use Symfony\Component\HttpFoundation\Response;

/**
 * The admin backend for MCP clients and blocked hosts (design §5.2), mounted
 * by McpOAuthAdminRoutes inside the product's admin middleware. The product
 * owns the page: the index answers JSON, and every write answers 204 to a
 * JSON call and redirects back for a form or Inertia post. Input is
 * validated here (a 422 on failure): the package does not depend on
 * illuminate/foundation, so it has no FormRequest. The permission is the
 * product's route middleware.
 */
final class ClientAdminController
{
    public function index(ClientAdminService $clientAdminService): JsonResponse
    {
        return new JsonResponse([
            'clients' => $clientAdminService->clients(),
            'blockedHosts' => $clientAdminService->blockedHosts(),
        ]);
    }

    public function block(Request $request, string $clientId, BlockClientAction $blockClientAction): Response
    {
        /** @var Client $client */
        $client = ClientAdminService::packageClients()->whereKey($clientId)->firstOrFail();
        $blockClientAction->execute($client, $request->user());

        return self::done($request);
    }

    /**
     * S40: 1 to 100 distinct client UUIDs.
     */
    public function bulkBlock(Request $request, BulkBlockClientsAction $bulkBlockClientsAction): Response
    {
        /** @var array{client_ids: list<string>} $validated */
        $validated = Validator::make($request->all(), [
            'client_ids' => ['required', 'list', 'min:1', 'max:100'],
            'client_ids.*' => ['required', 'string', 'uuid', 'distinct'],
        ])->validate();

        $bulkBlockClientsAction->execute($validated['client_ids'], $request->user());

        return self::done($request);
    }

    /**
     * A host (Unicode accepted, stored as ASCII), the match mode (subdomains
     * too unless `exact`) and an optional reason. A host that does not
     * normalise is a 422 on `host`.
     */
    public function blockHost(Request $request, BlockRedirectHostAction $blockRedirectHostAction, RedirectUriGuard $redirectUriGuard): Response
    {
        $validator = Validator::make($request->all(), [
            'host' => ['required', 'string', 'max:253'],
            'match_mode' => ['nullable', 'in:exact,host_and_subdomains'],
            'reason' => ['nullable', 'string', 'max:512'],
        ]);
        $validator->after(static function (ValidatorInstance $validator) use ($request, $redirectUriGuard): void {
            if ($validator->errors()->isNotEmpty()) {
                return;
            }

            try {
                $redirectUriGuard->normalizeHost($request->string('host')->toString());
            } catch (InvalidArgumentException $exception) {
                $validator->errors()->add('host', $exception->getMessage());
            }
        });
        /** @var array{host: string, match_mode?: string|null, reason?: string|null} $validated */
        $validated = $validator->validate();

        $blockRedirectHostAction->execute(
            $validated['host'],
            $request->user(),
            ($validated['match_mode'] ?? null) !== OAuthBlockedRedirectHost::MATCH_MODE_EXACT,
            $validated['reason'] ?? null,
        );

        return self::done($request);
    }

    public function unblockHost(Request $request, string $blockedHostId, UnblockRedirectHostAction $unblockRedirectHostAction): Response
    {
        $blockedHost = OAuthBlockedRedirectHost::query()->where('public_id', $blockedHostId)->firstOrFail();
        $unblockRedirectHostAction->execute($blockedHost, $request->user());

        return self::done($request);
    }

    private static function done(Request $request): Response
    {
        return $request->expectsJson() ? response()->noContent() : back();
    }
}
