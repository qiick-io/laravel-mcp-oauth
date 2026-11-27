<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Scope;
use LogicException;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\ConsentView;
use Qiick\McpOAuth\Data\ClientInfo;
use Qiick\McpOAuth\Data\ConsentPage;
use Qiick\McpOAuth\McpOAuthServer;
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
 *
 * What the page shows (consent text version, locale, resource) is stored in
 * the session beside Passport's `authToken`, so approve and deny record the
 * page the user saw (PendingAuthorizationRequestService).
 *
 * @internal
 */
final class ConsentPageService
{
    public function __construct(
        private readonly Container $container,
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly McpOAuthServer $mcpOAuthServer,
    ) {}

    /**
     * @param  array{request: Request, user: Authenticatable, client: Client, scopes: list<Scope>, authToken: string}  $parameters
     *
     * @throws LogicException when the version or the locale would not fit its consent record column
     */
    public function render(array $parameters): Response
    {
        $redirectUri = $parameters['request']->query('redirect_uri');
        $clientInfo = $this->clientInfo($parameters['client'], is_string($redirectUri) ? $redirectUri : null);

        $consentOptions = $this->container->make(ConsentProvider::class)
            ->options($parameters['request'], $parameters['user'], $clientInfo);
        /** @var array<string, string> $resourceScopes validated by the authorization middleware */
        $resourceScopes = $parameters['request']->attributes->get(ResourceIndicatorsService::REQUEST_ATTRIBUTE, []);
        $resource = array_key_first($resourceScopes) ?? $this->mcpOAuthServer->resourceIdentifier();
        $locale = app()->getLocale();

        // The oauth_consent_records columns: string(32) and string(16).
        if ($consentOptions->consentVersion !== null && mb_strlen($consentOptions->consentVersion) > 32) {
            throw new LogicException('The consent version must be at most 32 characters.');
        }

        if (mb_strlen($locale) > 16) {
            throw new LogicException('The application locale must be at most 16 characters to be recorded with consent.');
        }

        $renderedConsent = [
            'authToken' => $parameters['authToken'],
            'consentVersion' => $consentOptions->consentVersion,
            'locale' => $locale,
            'resource' => $resource,
        ];

        if ($resourceScopes !== []) {
            $renderedConsent['resourceScopes'] = $resourceScopes;
        }

        $parameters['request']->session()->put(PendingAuthorizationRequestService::RENDERED_CONSENT_SESSION_KEY, $renderedConsent);

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
            advanced: self::advancedRows($clientInfo, $resource, is_string($redirectUri) ? $redirectUri : $clientInfo->redirectUris[0]),
            resourceScopes: $resourceScopes,
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

        // Only package clients reach consent (ValidateAuthorizationRequestMiddleware), so the row exists.
        /** @var array{registration_source: string, client_uri: ?string, logo_uri: ?string, policy_uri: ?string, tos_uri: ?string, contacts: ?list<string>, software_id: ?string, software_version: ?string, metadata_document_url: ?string} $registered */
        $registered = OAuthClientMetadata::query()->where('client_id', $clientId)->firstOrFail()->only([
            'registration_source', 'client_uri', 'logo_uri', 'policy_uri', 'tos_uri',
            'contacts', 'software_id', 'software_version', 'metadata_document_url',
        ]);

        return new ClientInfo(
            id: $clientId,
            name: $clientName,
            redirectHost: $this->redirectUriGuard->displayHostOf($redirectUri ?? $registeredRedirectUris[0]),
            redirectUris: $registeredRedirectUris,
            registrationSource: $registered['registration_source'],
            clientUri: $registered['client_uri'],
            logoUri: $registered['logo_uri'],
            policyUri: $registered['policy_uri'],
            tosUri: $registered['tos_uri'],
            contacts: $registered['contacts'] ?? [],
            softwareId: $registered['software_id'],
            softwareVersion: $registered['software_version'],
            metadataDocumentUrl: $registered['metadata_document_url'],
            // The callback this approval returns to, not the whole registration:
            // a client with an https and a loopback callback still warns (S3).
            isRedirectLoopback: $this->redirectUriGuard->isLoopbackRedirectUri($redirectUri ?? $registeredRedirectUris[0]),
        );
    }

    /**
     * The page's Advanced section (closed by default, standards review §4):
     * the resource and the callback this approval returns to, then what the
     * client registered, each row only when it has a value.
     *
     * @return list<array{label: string, value: string}>
     */
    private static function advancedRows(ClientInfo $clientInfo, string $resource, string $returnUri): array
    {
        $software = trim(($clientInfo->softwareId ?? '').' '.($clientInfo->softwareVersion ?? ''));
        $rows = [
            'Client ID' => $clientInfo->metadataDocumentUrl ?? $clientInfo->id,
            'Registered through' => $clientInfo->registrationSource,
            'Resource' => $resource,
            'Returns to' => $returnUri,
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
}
