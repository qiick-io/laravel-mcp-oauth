<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Mcp\Server\Http\Controllers\OAuthRegisterController;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Events\McpClientRegistered;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Dynamic client registration (RFC 7591 / design §8.1). Extends laravel/mcp's
 * controller so every redirect_uri decision goes through {@see RedirectUriGuard}
 * (B3) before the parent validation and Passport create.
 */
final class RegisterClientController extends OAuthRegisterController
{
    public function __construct(
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly ConfigRepository $config,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        foreach ($this->stringRedirectUris($request->input('redirect_uris')) as $redirectUri) {
            if (! $this->isRedirectUriAllowedForRegistration($redirectUri)) {
                return response()->json([
                    'error' => 'invalid_redirect_uri', // @pest-mutate-ignore: RemoveArrayItem — RFC 7591 error object
                    'error_description' => 'One or more redirect_uris are not allowed.',
                ], 400);
            }
        }

        $globalCap = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.registrations_global_cap'),
            'registrations_global_cap',
            BoundedPositiveInt::REGISTRATIONS_GLOBAL_CAP_MAX,
        );

        if ($this->nonRevokedClientCount() >= $globalCap) {
            return response()->json([
                'error' => 'temporarily_unavailable', // @pest-mutate-ignore: RemoveArrayItem — RFC 6750 wire shape
                'error_description' => 'The global OAuth client registration cap has been reached.',
            ], 503);
        }

        $response = parent::__invoke($request);

        if ($response->getStatusCode() === 201) {
            $this->dispatchRegisteredEvent($response);
        }

        return $response;
    }

    protected function isValidRedirectUri(string $value): bool
    {
        return $this->isRedirectUriAllowedForRegistration($value);
    }

    /**
     * @param  array<string, mixed>  $validated
     */
    protected function resolveClientName(array $validated): string
    {
        foreach (['client_name', 'name'] as $nameKey) {
            $nameValue = $validated[$nameKey] ?? null;

            if (is_string($nameValue) && $nameValue !== '') {
                return $nameValue;
            }
        }

        $redirectUris = $validated['redirect_uris'] ?? null;

        if (! is_array($redirectUris)) {
            return 'MCP Client';
        }

        $firstRedirectUri = $redirectUris[0] ?? null;

        if (! is_string($firstRedirectUri)) {
            return 'MCP Client';
        }

        $displayHost = $this->redirectUriGuard->displayHostOf($firstRedirectUri);

        return $displayHost !== '' ? $displayHost : 'MCP Client';
    }

    private function isRedirectUriAllowedForRegistration(string $redirectUri): bool
    {
        // isAcceptableForRegistration already applies the scheme allow-list via
        // the same canonical parse; a second isAllowedScheme call would only
        // duplicate mutants without a behavioural fork.
        if (! $this->redirectUriGuard->isAcceptableForRegistration($redirectUri)) {
            return false;
        }

        $host = $this->redirectUriGuard->hostOf($redirectUri);

        return $host === null || ! $this->redirectUriGuard->isHostBlocked($host);
    }

    /**
     * @return list<string>
     */
    private function stringRedirectUris(mixed $redirectUris): array
    {
        if (! is_array($redirectUris)) {
            return [];
        }

        $strings = [];

        foreach ($redirectUris as $redirectUri) {
            if (is_string($redirectUri)) {
                $strings[] = $redirectUri;
            }
        }

        return $strings;
    }

    private function dispatchRegisteredEvent(JsonResponse $response): void
    {
        $payload = $response->getData(true);

        if (! is_array($payload)) {
            return;
        }

        $clientId = $payload['client_id'] ?? null;
        $registeredRedirectUris = $payload['redirect_uris'] ?? null;

        if (! is_string($clientId) || $clientId === '' || ! is_array($registeredRedirectUris)) {
            return;
        }

        event(new McpClientRegistered(
            $clientId,
            $this->displayHostsFromRedirectUris($registeredRedirectUris),
        ));
    }

    /**
     * @param  array<mixed>  $redirectUris
     * @return list<string>
     */
    private function displayHostsFromRedirectUris(array $redirectUris): array
    {
        $displayHosts = [];

        foreach ($redirectUris as $redirectUri) {
            if (! is_string($redirectUri)) {
                continue;
            }

            $displayHost = $this->redirectUriGuard->displayHostOf($redirectUri);

            if ($displayHost !== '' && ! in_array($displayHost, $displayHosts, true)) {
                $displayHosts[] = $displayHost;
            }
        }

        return $displayHosts;
    }

    private function nonRevokedClientCount(): int
    {
        return Client::query()->where('revoked', false)->count();
    }
}
