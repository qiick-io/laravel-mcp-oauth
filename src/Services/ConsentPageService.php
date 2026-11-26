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
use Qiick\McpOAuth\Models\OAuthClientMetadata;
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
                'isRedirectLoopback' => $clientInfo->isRedirectLoopback,
            ],
            authToken: $parameters['authToken'],
            options: $consentOptions,
            advanced: self::advancedRows($clientInfo),
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

        $metadata = OAuthClientMetadata::query()->where('client_id', $clientId)->first();
        /** @var list<string> $contacts */
        $contacts = $metadata?->getAttribute('contacts') ?? [];

        return new ClientInfo(
            id: $clientId,
            name: $clientName,
            redirectHost: $this->redirectUriGuard->displayHostOf($redirectUri ?? $registeredRedirectUris[0]),
            redirectUris: $registeredRedirectUris,
            registrationSource: self::stringOrNull($metadata?->getAttribute('registration_source')) ?? 'dcr',
            clientUri: self::stringOrNull($metadata?->getAttribute('client_uri')),
            logoUri: self::stringOrNull($metadata?->getAttribute('logo_uri')),
            policyUri: self::stringOrNull($metadata?->getAttribute('policy_uri')),
            tosUri: self::stringOrNull($metadata?->getAttribute('tos_uri')),
            contacts: $contacts,
            softwareId: self::stringOrNull($metadata?->getAttribute('software_id')),
            softwareVersion: self::stringOrNull($metadata?->getAttribute('software_version')),
            metadataDocumentUrl: self::stringOrNull($metadata?->getAttribute('metadata_document_url')),
            // The callback this approval returns to, not the whole registration:
            // a client with an https and a loopback callback still warns (S3).
            isRedirectLoopback: $this->redirectUriGuard->isLoopbackRedirectUri($redirectUri ?? $registeredRedirectUris[0]),
        );
    }

    /**
     * The page's Advanced section (closed by default, standards review §4):
     * what the client registered, each row only when it has a value.
     *
     * @return list<array{label: string, value: string}>
     */
    private static function advancedRows(ClientInfo $clientInfo): array
    {
        $software = trim(($clientInfo->softwareId ?? '').' '.($clientInfo->softwareVersion ?? ''));
        $rows = [
            'Client ID' => $clientInfo->id,
            'Registered through' => $clientInfo->registrationSource,
            'Callbacks' => implode(', ', $clientInfo->redirectUris),
            'Website' => $clientInfo->clientUri,
            'Terms' => $clientInfo->tosUri,
            'Privacy policy' => $clientInfo->policyUri,
            'Contacts' => implode(', ', $clientInfo->contacts),
            'Software' => $software,
        ];

        $advancedRows = [];

        foreach ($rows as $label => $value) {
            if ($value !== null && $value !== '') {
                $advancedRows[] = ['label' => $label, 'value' => $value];
            }
        }

        return $advancedRows;
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
