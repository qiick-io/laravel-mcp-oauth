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
        $redirectUris = $request->input('redirect_uris');

        if (is_array($redirectUris)) {
            foreach ($redirectUris as $redirectUri) {
                if (! is_string($redirectUri) || ! $this->isRedirectUriAllowedForRegistration($redirectUri)) {
                    return response()->json([
                        'error' => 'invalid_redirect_uri',
                        'error_description' => 'One or more redirect_uris are not allowed.',
                    ], 400);
                }
            }
        }

        $globalCap = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.registrations_global_cap', 10_000),
            'registrations_global_cap',
            100_000,
        );

        if ($this->nonRevokedClientCount() >= $globalCap) {
            return response()->json([
                'error' => 'temporarily_unavailable',
                'error_description' => 'The global OAuth client registration cap has been reached.',
            ], 503);
        }

        $response = parent::__invoke($request);

        if ($response->getStatusCode() === 201) {
            $payload = $response->getData(true);

            if (is_array($payload)) {
                $clientId = isset($payload['client_id']) && is_string($payload['client_id'])
                    ? $payload['client_id']
                    : '';
                $registeredRedirectUris = $payload['redirect_uris'] ?? [];

                if ($clientId !== '' && is_array($registeredRedirectUris)) {
                    // Parent already persisted the client; fire after the write succeeds.
                    event(new McpClientRegistered(
                        $clientId,
                        $this->displayHostsFromRedirectUris($registeredRedirectUris),
                    ));
                }
            }
        }

        return $response;
    }

    protected function isValidRedirectUri(string $value): bool
    {
        return $this->isRedirectUriAllowedForRegistration($value);
    }

    protected function resolveClientName(array $validated): string
    {
        if (isset($validated['client_name']) && is_string($validated['client_name']) && $validated['client_name'] !== '') {
            return $validated['client_name'];
        }

        if (isset($validated['name']) && is_string($validated['name']) && $validated['name'] !== '') {
            return $validated['name'];
        }

        $redirectUris = $validated['redirect_uris'] ?? null;

        if (is_array($redirectUris)) {
            $firstRedirectUri = $redirectUris[0] ?? null;

            if (is_string($firstRedirectUri)) {
                $displayHost = $this->redirectUriGuard->displayHostOf($firstRedirectUri);

                if ($displayHost !== '') {
                    return $displayHost;
                }
            }
        }

        return 'MCP Client';
    }

    private function isRedirectUriAllowedForRegistration(string $redirectUri): bool
    {
        if (! $this->redirectUriGuard->isAcceptableForRegistration($redirectUri)) {
            return false;
        }

        if (! $this->redirectUriGuard->isAllowedScheme($redirectUri)) {
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn — same gate as isAcceptable today
        }

        try {
            $host = $this->redirectUriGuard->hostOf($redirectUri);
        } catch (\InvalidArgumentException) {
            return false;
        }

        if ($host !== null && $this->redirectUriGuard->isHostBlocked($host)) {
            return false;
        }

        return true;
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
