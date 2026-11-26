<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\RedirectUriGuard;
use Qiick\McpOAuth\Services\TokenErrorResponseService;
use Symfony\Component\HttpFoundation\Response;

/**
 * What `POST oauth/token` requires before league sees the request (design
 * §5.2 item 6, S16, S19, S37, S38):
 *
 * - `grant_type` is one of {@see McpOAuthServer::supportedGrantTypes()}
 *   (`client_credentials`, `password`, the device grant and anything else are
 *   `unsupported_grant_type`, even if Passport would enable one later);
 * - the RFC 8707 `resource` names this server's MCP endpoint, on the code
 *   exchange and on every refresh (MCP authorization requires it on both);
 * - the client, named in the body or as the HTTP Basic username (never
 *   both, RFC 6749 §2.3), is a UUID, was registered by the package (its
 *   `oauth_client_metadata` row, so every token minted here is bound) and
 *   none of its redirect hosts is blocked.
 *
 * A revoked client is left to league, which answers the same
 * `invalid_client`. PKCE, the code and the refresh token are league's
 * checks; {@see TokenErrorResponseService} renders every refusal.
 */
final class ValidateTokenRequestMiddleware
{
    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly TokenErrorResponseService $tokenErrorResponses,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $bodyParameters = $request->request->all();

        if (! in_array($bodyParameters['grant_type'] ?? null, McpOAuthServer::supportedGrantTypes(), true)) {
            // Second guard: the provider also strips every other grant from the server,
            // and league then answers with this same body.
            return $this->tokenErrorResponses->refusal('unsupported_grant_type');
        }

        if (! $this->mcpOAuthServer->acceptsResource($bodyParameters['resource'] ?? null)) {
            return $this->tokenErrorResponses->refusal('invalid_target');
        }

        $basicClientId = $request->getUser();
        $hasBodyCredentials = ($bodyParameters['client_id'] ?? null) !== null || ($bodyParameters['client_secret'] ?? null) !== null;

        // RFC 6749 §2.3: one authentication method per request, never Basic and the body together.
        if ($basicClientId !== null && $hasBodyCredentials) {
            return $this->tokenErrorResponses->refusal('invalid_request');
        }

        // League's order: the body, else the Basic username.
        $clientId = $bodyParameters['client_id'] ?? $basicClientId;

        // Missing, empty or repeated: league answers invalid_request.
        if (! is_string($clientId) || $clientId === '') {
            return $next($request);
        }

        // A non-UUID would make PostgreSQL throw on the uuid column.
        if (! Str::isUuid($clientId)
            || ! OAuthClientMetadata::isRegisteredClient($clientId)
            || $this->clientHasBlockedRedirectHost($clientId)) {
            return $this->tokenErrorResponses->invalidClient($request);
        }

        return $next($request);
    }

    private function clientHasBlockedRedirectHost(string $clientId): bool
    {
        /** @var Client|null $client */
        $client = Passport::client()->newQuery()
            ->whereKey($clientId)
            ->where('revoked', false)
            ->first();

        return $client !== null && $this->redirectUriGuard->clientHasBlockedRedirectHost($client);
    }
}
