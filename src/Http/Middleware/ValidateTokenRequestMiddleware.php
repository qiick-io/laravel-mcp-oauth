<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Data\TokenResourceSelectionData;
use Qiick\McpOAuth\Exceptions\ClientMetadataUnavailableException;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\RedirectUriGuard;
use Qiick\McpOAuth\Services\ClientMetadataRegistryService;
use Qiick\McpOAuth\Services\ResourceIndicatorsService;
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
 *   both, RFC 6749 §2.3), is a UUID or a public CIMD URL, was registered by the package (its
 *   `oauth_client_metadata` row, so every token minted here is bound) and
 *   none of its redirect hosts is blocked.
 *
 * A revoked client is left to league, which answers the same
 * `invalid_client`. PKCE, the code and the refresh token are league's
 * checks; {@see TokenErrorResponseService} renders every refusal.
 *
 * @internal
 */
final class ValidateTokenRequestMiddleware
{
    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly TokenErrorResponseService $tokenErrorResponses,
        private readonly ClientMetadataRegistryService $metadataClients,
        private readonly ResourceIndicatorsService $resourceIndicators,
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

        $hasAdditionalResources = $this->mcpOAuthServer->registeredResources() !== [];

        if (! $hasAdditionalResources && ! $this->mcpOAuthServer->acceptsResource($bodyParameters['resource'] ?? null)) {
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

        if (Str::isUuid($clientId)) {
            if (! $this->metadataClients->isRegisteredWireUuid($clientId) || $this->clientHasBlockedRedirectHost($clientId)) {
                return $this->tokenErrorResponses->invalidClient($request);
            }
        } else {
            $resolution = $this->resolveMetadataClient($request, $clientId, $basicClientId);

            if ($resolution instanceof Response) {
                return $resolution;
            }

            $clientId = $resolution;
        }

        if ($hasAdditionalResources) {
            $body = $request->getContent();
            $indicators = $this->resourceIndicators->parse($body, $bodyParameters['resource'] ?? null, 'resource') ?? [];
            $resourceScopes = count($indicators) === 1 ? $this->resourceIndicators->resolve($indicators, $clientId) : [];
            $resource = array_key_first($resourceScopes);

            if ($resource === null) {
                return $this->tokenErrorResponses->refusal('invalid_target');
            }

            $scope = $resourceScopes[$resource];
            $requestedScopes = $this->resourceIndicators->parse($body, $bodyParameters['scope'] ?? null, 'scope');

            if ($requestedScopes !== [] && $requestedScopes !== [$scope]) {
                return $this->tokenErrorResponses->refusal('invalid_scope');
            }

            $request->attributes->set(
                TokenResourceSelectionData::REQUEST_ATTRIBUTE,
                new TokenResourceSelectionData($resource, $scope),
            );
        }

        return $next($request);
    }

    /**
     * Only previously associated public clients can exchange a code or refresh;
     * token requests cannot create a registration or use a client secret.
     */
    private function resolveMetadataClient(Request $request, string $clientId, ?string $basicClientId): string|Response
    {
        $parameters = $request->request->all();

        if ($basicClientId !== null || isset($parameters['client_secret']) || isset($parameters['client_assertion']) || isset($parameters['client_assertion_type'])) {
            return $this->tokenErrorResponses->invalidClient($request);
        }

        try {
            $client = $this->metadataClients->resolve($clientId);
        } catch (ClientMetadataUnavailableException) {
            return $this->tokenErrorResponses->refusal('temporarily_unavailable', 503);
        }

        $resolvedClientId = $client?->getKey();

        if ($client === null || ! is_string($resolvedClientId) || $this->redirectUriGuard->clientHasBlockedRedirectHost($client)) {
            return $this->tokenErrorResponses->invalidClient($request);
        }

        if ($parameters['grant_type'] === 'authorization_code') {
            $redirectUri = $parameters['redirect_uri'] ?? null;
            /** @var list<string> $registeredRedirectUris Passport casts the column to a list */
            $registeredRedirectUris = $client->getAttribute('redirect_uris');

            if ($redirectUri !== null && ! in_array($redirectUri, $registeredRedirectUris, true)) {
                return $this->tokenErrorResponses->refusal('invalid_grant');
            }
        }

        $request->request->set('client_id', $resolvedClientId);

        return $resolvedClientId;
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
