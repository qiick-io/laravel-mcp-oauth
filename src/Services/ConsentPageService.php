<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Scope;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\ConsentView;
use Qiick\McpOAuth\Data\ClientInfo;
use Qiick\McpOAuth\Data\ConsentPage;
use Qiick\McpOAuth\RedirectUriGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Builds the consent page from Passport's authorization view parameters and
 * hands it to the product's {@see ConsentView} (design §8.3 step 3, S44).
 *
 * The client name is the client's own claim, so the page always carries the
 * host the grant returns to: the request's `redirect_uri` (already checked by
 * ValidateAuthorizationRequestMiddleware), or the client's only URI.
 * ConsentProvider and ConsentView are resolved per render, so a product that
 * has not bound them yet still boots while OAuth is off.
 */
final class ConsentPageService
{
    public function __construct(
        private readonly Container $container,
        private readonly RedirectUriGuard $redirectUriGuard,
    ) {}

    /**
     * @param  array{request: Request, user: Authenticatable, client: Client, scopes: list<Scope>, authToken: string}  $parameters
     */
    public function render(array $parameters): Response
    {
        $redirectUri = $parameters['request']->query('redirect_uri');
        $clientInfo = $this->clientInfo($parameters['client'], is_string($redirectUri) ? $redirectUri : null);

        $consentOptions = $this->container->make(ConsentProvider::class)
            ->options($parameters['request'], $parameters['user'], $clientInfo);

        $consentPage = new ConsentPage(
            client: [
                'id' => $clientInfo->id,
                'name' => $clientInfo->name,
                'redirectHost' => $clientInfo->redirectHost,
                'nameIsSelfAsserted' => true,
                'isRedirectLoopbackOnly' => $clientInfo->isRedirectLoopbackOnly,
            ],
            authToken: $parameters['authToken'],
            options: $consentOptions,
        );

        return $this->container->make(ConsentView::class)->render($parameters, $consentPage);
    }

    /**
     * @param  string|null  $redirectUri  the request's validated URI; null uses the client's first
     */
    public function clientInfo(Client $client, ?string $redirectUri): ClientInfo
    {
        // Passport casts redirect_uris to a list of strings; DCR stores at least one.
        /** @var non-empty-list<string> $registeredRedirectUris */
        $registeredRedirectUris = $client->getAttribute('redirect_uris');
        /** @var string $clientId Passport client ids are UUID strings */
        $clientId = $client->getKey();
        /** @var string $clientName */
        $clientName = $client->getAttribute('name');

        return new ClientInfo(
            id: $clientId,
            name: $clientName,
            redirectHost: $this->redirectUriGuard->displayHostOf($redirectUri ?? $registeredRedirectUris[0]),
            redirectUris: $registeredRedirectUris,
            isRedirectLoopbackOnly: array_filter(
                $registeredRedirectUris,
                fn (string $registeredRedirectUri): bool => ! $this->redirectUriGuard->isLoopbackRedirectUri($registeredRedirectUri),
            ) === [],
        );
    }
}
