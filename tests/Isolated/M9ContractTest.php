<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcher;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\ConsentOptions;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpConsentApproved;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Testing\FakeGrantStore;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * The @api contract additions of the standards review (§3, M9), landed before
 * 1.0 because adding a field or a case later breaks adopters.
 */
beforeEach(function (): void {
    McpOAuthRoutes::register();
});

it('carries the resource, the consent text version and the locale on the decision, the record and the event', function (): void {
    Event::fake([McpConsentApproved::class]);
    $defaults = AuthorizeFlowTestCase::defaultConsentOptions();
    $this->enableOAuth(new ConsentOptions(
        scopes: $defaults->scopes,
        roles: $defaults->roles,
        resources: $defaults->resources,
        resourcesRequired: $defaults->resourcesRequired,
        canGrant: true,
        consentVersion: '2026-11',
    ));
    app()->setLocale('it');

    $this->obtainAuthorizationCode($this->createClient());

    $decision = $this->grantStore()->replacedDecisions[0];

    expect($decision->resource)->toBe(AuthorizeFlowTestCase::RESOURCE)
        ->and($decision->consentVersion)->toBe('2026-11')
        ->and($decision->locale)->toBe('it')
        ->and(OAuthConsentRecord::query()->sole()->getAttribute('consent_version'))->toBe('2026-11');

    Event::assertDispatched(McpConsentApproved::class, static fn (McpConsentApproved $event): bool => $event->resource === AuthorizeFlowTestCase::RESOURCE);
});

it('gives the product every registered client field, and the page an advanced section', function (): void {
    $consentProvider = $this->enableOAuth();
    $client = $this->createClient(['https://app.example/callback', 'https://app.example/second']);
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'client_uri' => 'https://app.example',
        'logo_uri' => 'https://app.example/logo.png',
        'tos_uri' => 'https://app.example/terms',
        'policy_uri' => 'https://app.example/privacy',
        'contacts' => ['security@app.example'],
        'software_id' => 'cursor',
        'software_version' => '2.1.0',
    ]);

    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();

    $clientInfo = $consentProvider->askedClients[0];

    expect($clientInfo->registrationSource)->toBe('dcr')
        ->and($clientInfo->clientUri)->toBe('https://app.example')
        ->and($clientInfo->logoUri)->toBe('https://app.example/logo.png')
        ->and($clientInfo->tosUri)->toBe('https://app.example/terms')
        ->and($clientInfo->policyUri)->toBe('https://app.example/privacy')
        ->and($clientInfo->contacts)->toBe(['security@app.example'])
        ->and($clientInfo->softwareId)->toBe('cursor')
        ->and($clientInfo->softwareVersion)->toBe('2.1.0')
        ->and($clientInfo->metadataDocumentUrl)->toBeNull()
        ->and($clientInfo->nameIsSelfAsserted)->toBeTrue()
        ->and($page->json('props.advanced'))->toBe([
            ['label' => 'Client ID', 'value' => (string) $client->getKey()],
            ['label' => 'Registered through', 'value' => 'dcr'],
            ['label' => 'Callbacks', 'value' => 'https://app.example/callback, https://app.example/second'],
            ['label' => 'Website', 'value' => 'https://app.example'],
            ['label' => 'Terms', 'value' => 'https://app.example/terms'],
            ['label' => 'Privacy policy', 'value' => 'https://app.example/privacy'],
            ['label' => 'Contacts', 'value' => 'security@app.example'],
            ['label' => 'Software', 'value' => 'cursor 2.1.0'],
        ]);
});

it('leaves out the advanced rows a client did not register', function (): void {
    $this->enableOAuth();
    $client = $this->createClient();

    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();

    expect(array_column($page->json('props.advanced'), 'label'))->toBe(['Client ID', 'Registered through', 'Callbacks']);
});

it('tells when and why a grant was revoked', function (): void {
    $grantStore = new FakeGrantStore;
    $grant = $grantStore->replace(new ConsentDecision((string) Str::uuid7(), '1', 'https://app.example/callback', ['mcp:read'], null, [], false));

    expect($grant->revokedAt)->toBeNull()
        ->and($grant->revocationReason)->toBeNull()
        ->and($grant->metadata)->toBe([]);

    $grantStore->revoke($grant->id, '1', RevocationReason::Security);
    $revokedGrant = $grantStore->find($grant->id);

    expect($revokedGrant?->revokedAt)->not->toBeNull()
        ->and($revokedGrant?->revocationReason)->toBe(RevocationReason::Security);
});

it('names security as a revocation reason and declares the CIMD fetcher contract', function (): void {
    expect(RevocationReason::Security->value)->toBe('security')
        ->and(interface_exists(ClientMetadataDocumentFetcher::class))->toBeTrue();
});
