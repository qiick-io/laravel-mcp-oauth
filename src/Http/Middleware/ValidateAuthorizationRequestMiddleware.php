<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Data\GrantInstallationData;
use Qiick\McpOAuth\Exceptions\ClientMetadataUnavailableException;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\RedirectUriGuard;
use Qiick\McpOAuth\Services\ClientMetadataRegistryService;
use Qiick\McpOAuth\Services\ResourceIndicatorsService;
use Symfony\Component\HttpFoundation\Response;

/**
 * What `GET oauth/authorize` requires before Passport and league see the
 * request (design §8.3 step 1, S16, S17, S20, S37):
 *
 * - `response_type=code`, a `code_challenge` and `code_challenge_method=S256`
 *   (OAuth 2.1; `plain` and missing PKCE are refused even for confidential
 *   clients, which league would let through); the challenge format
 *   (RFC 7636 §4.2) is league's check;
 * - the RFC 8707 `resource` names this server's MCP endpoint;
 * - the client is registered by the package through DCR or CIMD, is active
 *   and has no blocked redirect host. Passport only receives its internal UUID;
 * - `redirect_uri` equals one registered URI under
 *   {@see RedirectUriGuard::areExactlyEqual()}, or is omitted while the client
 *   has exactly one. League would accept another port on a loopback URI
 *   (RFC 8252 §7.3); here the port must match too, because DCR clients
 *   register the exact URI they listen on. League then compares the raw
 *   strings, so a host-case or empty-query variant that passes here is still
 *   refused there (as `invalid_client`, without a redirect).
 *
 * Refusals are local JSON responses: the redirect URI is not
 * trusted yet, and RFC 6749 §4.1.2.1 forbids redirecting to an unvalidated
 * one. A repeated (array) parameter league reads is refused by league itself
 * as a JSON `invalid_request`. The MCP-only flow drops the requested scope
 * (RFC 6749 §3.3) and lets Passport apply its default, `mcp:use`.
 *
 * @internal
 */
final class ValidateAuthorizationRequestMiddleware
{
    public const string INSTALLATION_ATTRIBUTE = 'mcp_oauth_grant_installation';

    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly ClientMetadataRegistryService $metadataClients,
        private readonly ResourceIndicatorsService $resourceIndicators,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $refusal = $this->refusalFor($request);

        if ($refusal !== null) {
            return $refusal;
        }

        /** @var array<string, string>|null $resourceScopes set by registeredResourceRefusal for the additional resources */
        $resourceScopes = $request->attributes->get(ResourceIndicatorsService::REQUEST_ATTRIBUTE);

        if ($resourceScopes !== null) {
            $request->query->set('scope', implode(' ', $resourceScopes));
        } else {
            $request->query->remove('scope');
        }

        $this->dropPromptLogin($request);
        $response = $next($request);

        if ($resourceScopes !== null && $response->isRedirect() && $request->hasSession()) {
            $this->preserveResourceIndicatorsForLogin($request);
        }

        return $response;
    }

    /**
     * Laravel stores the normalized URL on its login redirect. Symfony's
     * normalization collapses repeated RFC 8707 resource indicators.
     */
    private function preserveResourceIndicatorsForLogin(Request $request): void
    {
        $query = $request->server->get('QUERY_STRING');
        $session = $request->session();

        if (is_string($query) && $session->get('url.intended') === $request->fullUrl()) {
            $session->put('url.intended', $this->mcpOAuthServer->issuer().'/oauth/authorize?'.$query);
        }
    }

    /**
     * Passport answers `prompt=login` by signing the user out with a GET, and
     * anyone can register a client, so the link would be a logout CSRF. MCP
     * clients have no use for it; `none` and `consent` keep working.
     */
    private function dropPromptLogin(Request $request): void
    {
        $prompt = $request->query('prompt');

        if (! is_string($prompt)) {
            return;
        }

        $promptValues = array_diff(explode(' ', $prompt), ['login']);
        $request->query->set('prompt', implode(' ', $promptValues));
    }

    private function refusalFor(Request $request): ?JsonResponse
    {
        if ($request->query('response_type') !== 'code') {
            return self::oauthError('unsupported_response_type', 'Only response_type=code is supported.');
        }

        $codeChallenge = $request->query('code_challenge');

        // ConvertEmptyStringsToNull turns `code_challenge=` into null.
        if ($request->query('code_challenge_method') !== 'S256' || ! is_string($codeChallenge)) {
            return self::oauthError('invalid_request', 'PKCE with code_challenge_method S256 is required.');
        }

        $hasAdditionalResources = $this->mcpOAuthServer->registeredResources() !== [];

        if (! $hasAdditionalResources && ! $this->mcpOAuthServer->acceptsResource($request->query->all()['resource'] ?? null)) {
            return self::oauthError('invalid_target', 'The resource parameter is required and must name this MCP endpoint.');
        }

        $clientId = $request->query('client_id');

        if (! is_string($clientId)) {
            return self::oauthError('invalid_client', 'The client is unknown, revoked or blocked on this server.');
        }

        $isUuid = Str::isUuid($clientId);

        try {
            $client = $isUuid ? $this->activeClient($clientId) : $this->metadataClients->resolve($clientId, canRegister: true);
        } catch (ClientMetadataUnavailableException) {
            return self::oauthError('temporarily_unavailable', 'Client metadata is temporarily unavailable.', 503);
        }

        $resolvedClientId = $client?->getKey();

        if ($client === null || ! is_string($resolvedClientId)
            || $this->redirectUriGuard->clientHasBlockedRedirectHost($client)) {
            return self::oauthError('invalid_client', 'The client is unknown, revoked or blocked on this server.');
        }

        if (! $this->isRegisteredRedirectUri($client, $request->query('redirect_uri'), ! $isUuid)) {
            return self::oauthError('invalid_request', 'The redirect_uri is not registered for this client.');
        }

        $installationRefusal = $this->installationRefusal($request, $resolvedClientId);

        if ($installationRefusal !== null) {
            return $installationRefusal;
        }

        if (! $isUuid) {
            $request->query->set('client_id', $resolvedClientId);
        }

        if ($hasAdditionalResources) {
            return $this->registeredResourceRefusal($request, $resolvedClientId);
        }

        return null;
    }

    private function installationRefusal(Request $request, string $clientId): ?JsonResponse
    {
        $wireQuery = $request->server->get('QUERY_STRING');
        $wireQuery = is_string($wireQuery) ? $wireQuery : '';
        $parameters = $request->query->all();
        $installIds = $this->resourceIndicators->parse($wireQuery, $parameters['install_id'] ?? null, 'install_id');
        $keyThumbprints = $this->resourceIndicators->parse($wireQuery, $parameters['companion_jkt'] ?? null, 'companion_jkt');

        if (! OAuthClientMetadata::isPerInstallClient($clientId)) {
            return $installIds === [] && $keyThumbprints === []
                ? null
                : self::oauthError('invalid_request', 'This client does not accept installation parameters.');
        }

        $installId = $installIds[0] ?? '';
        $keyThumbprint = $keyThumbprints[0] ?? '';

        if ($installIds === null || count($installIds) !== 1 || ! Str::isUuid($installId, 4)
            || $keyThumbprints === null || count($keyThumbprints) !== 1 || preg_match('/\A[A-Za-z0-9_-]{43}\z/', $keyThumbprint) !== 1) {
            return self::oauthError('invalid_request', 'A random UUIDv4 installation id and SHA-256 key thumbprint are required.');
        }

        $request->attributes->set(self::INSTALLATION_ATTRIBUTE, new GrantInstallationData(strtolower($installId), $keyThumbprint));

        return null;
    }

    private function registeredResourceRefusal(Request $request, string $clientId): ?JsonResponse
    {
        $query = $request->server->get('QUERY_STRING');
        $query = is_string($query) ? $query : '';
        $queryParameters = $request->query->all();
        $indicators = $this->resourceIndicators->parse(
            $query,
            $queryParameters['resource'] ?? null,
            'resource',
        );
        $resourceScopes = $this->resourceIndicators->resolve($indicators ?? [], $clientId);

        if ($resourceScopes === []) {
            return self::oauthError('invalid_target', 'Each resource must be known, unique and available to this client.');
        }

        $requestedScopes = $this->resourceIndicators->parse($query, $queryParameters['scope'] ?? null, 'scope');

        if ($requestedScopes === null || count($requestedScopes) > 1
            || ! $this->resourceIndicators->allowsRequestedScope($requestedScopes[0] ?? null, $resourceScopes)) {
            return self::oauthError('invalid_scope', 'A requested scope is outside the selected resources.');
        }

        if ($resourceScopes !== [$this->mcpOAuthServer->resourceIdentifier() => McpOAuthServer::WIRE_SCOPE]) {
            $request->attributes->set(ResourceIndicatorsService::REQUEST_ATTRIBUTE, $resourceScopes);
        }

        return null;
    }

    private function activeClient(string $clientId): ?Client
    {
        if (! $this->metadataClients->isRegisteredWireUuid($clientId)) {
            return null;
        }

        /** @var Client|null $client */
        $client = Passport::client()->newQuery()
            ->whereKey($clientId)
            ->where('revoked', false)
            ->first();

        return $client;
    }

    private function isRegisteredRedirectUri(Client $client, mixed $redirectUri, bool $requiresLiteralMatch): bool
    {
        /** @var list<string> $registeredRedirectUris Passport casts the column to a list */
        $registeredRedirectUris = $client->getAttribute('redirect_uris');

        // Omitted (an empty value arrives as null): league falls back to the
        // client's URI only when it has exactly one.
        if ($redirectUri === null) {
            return count($registeredRedirectUris) === 1;
        }

        return is_string($redirectUri) && ($requiresLiteralMatch
            ? in_array($redirectUri, $registeredRedirectUris, true)
            : $this->redirectUriGuard->clientHasExactRedirectUri($client, $redirectUri));
    }

    /**
     * An RFC 6749 §5.2-shaped error body, never a redirect.
     */
    private static function oauthError(string $error, string $description, int $status = 400): JsonResponse
    {
        return new JsonResponse(['error' => $error, 'error_description' => $description], $status, ['Cache-Control' => 'no-store']);
    }
}
