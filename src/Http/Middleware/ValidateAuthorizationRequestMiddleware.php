<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\RedirectUriGuard;
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
 * - the client exists, is not revoked, was registered by the package (its
 *   `oauth_client_metadata` row: a product's own Passport client never gets
 *   an MCP token that nothing binds) and none of its redirect hosts is
 *   blocked;
 * - `redirect_uri` equals one registered URI under
 *   {@see RedirectUriGuard::areExactlyEqual()}, or is omitted while the client
 *   has exactly one. League would accept another port on a loopback URI
 *   (RFC 8252 §7.3); here the port must match too, because DCR clients
 *   register the exact URI they listen on. League then compares the raw
 *   strings, so a host-case or empty-query variant that passes here is still
 *   refused there (as `invalid_client`, without a redirect).
 *
 * Every refusal is a JSON 400 and never a redirect: the redirect URI is not
 * trusted yet, and RFC 6749 §4.1.2.1 forbids redirecting to an unvalidated
 * one. A repeated (array) parameter league reads is refused by league itself
 * as a JSON `invalid_request`. The requested scope is dropped (RFC 6749 §3.3):
 * league then applies Passport's default, `mcp:use`.
 */
final class ValidateAuthorizationRequestMiddleware
{
    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly RedirectUriGuard $redirectUriGuard,
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

        // The token only ever carries `mcp:use`, Passport's default scope, so the
        // requested scope is dropped instead of echoed or refused (S20).
        $request->query->remove('scope');
        $this->dropPromptLogin($request);

        return $next($request);
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

        if (! $this->mcpOAuthServer->acceptsResource($request->query->all()['resource'] ?? null)) {
            return self::oauthError('invalid_target', 'The resource parameter is required and must name this MCP endpoint.');
        }

        $client = $this->activeClient($request->query('client_id'));

        if ($client === null
            || ! OAuthClientMetadata::isRegisteredClient($client)
            || $this->redirectUriGuard->clientHasBlockedRedirectHost($client)) {
            return self::oauthError('invalid_client', 'The client is unknown, revoked or blocked on this server.');
        }

        if (! $this->isRegisteredRedirectUri($client, $request->query('redirect_uri'))) {
            return self::oauthError('invalid_request', 'The redirect_uri is not registered for this client.');
        }

        return null;
    }

    private function activeClient(mixed $clientId): ?Client
    {
        // A non-UUID would make PostgreSQL throw on the uuid column.
        if (! Str::isUuid($clientId)) {
            return null;
        }

        /** @var Client|null $client */
        $client = Passport::client()->newQuery()
            ->whereKey($clientId)
            ->where('revoked', false)
            ->first();

        return $client;
    }

    private function isRegisteredRedirectUri(Client $client, mixed $redirectUri): bool
    {
        // Omitted (an empty value arrives as null): league falls back to the
        // client's URI only when it has exactly one.
        if ($redirectUri === null) {
            /** @var list<string> $registeredRedirectUris Passport casts the column to a list */
            $registeredRedirectUris = $client->getAttribute('redirect_uris');

            return count($registeredRedirectUris) === 1;
        }

        return is_string($redirectUri) && $this->redirectUriGuard->clientHasExactRedirectUri($client, $redirectUri);
    }

    /**
     * An RFC 6749 §5.2-shaped error body, never a redirect.
     */
    private static function oauthError(string $error, string $description): JsonResponse
    {
        return new JsonResponse(['error' => $error, 'error_description' => $description], 400);
    }
}
