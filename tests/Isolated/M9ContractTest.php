<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\ConsentOptions;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpConsentApprovedEvent;
use Qiick\McpOAuth\Internal\ClientMetadataDocumentFetcher;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Services\PendingAuthorizationRequestService;
use Qiick\McpOAuth\Testing\FakeConsentProvider;
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
    Event::fake([McpConsentApprovedEvent::class]);
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

    Event::assertDispatched(McpConsentApprovedEvent::class, static fn (McpConsentApprovedEvent $event): bool => $event->resource === AuthorizeFlowTestCase::RESOURCE);
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
            ['label' => 'Resource', 'value' => AuthorizeFlowTestCase::RESOURCE],
            ['label' => 'Returns to', 'value' => 'https://app.example/callback'],
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

    expect(array_column($page->json('props.advanced'), 'label'))->toBe(['Client ID', 'Registered through', 'Resource', 'Returns to', 'Callbacks']);
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

it('names security as a revocation reason', function (): void {
    expect(RevocationReason::Security->value)->toBe('security');
});

it('keeps the CIMD fetcher internal until its runtime proves the seam (Codex review of #59)', function (): void {
    $fetcher = new ReflectionClass(ClientMetadataDocumentFetcher::class);

    expect($fetcher->isInterface())->toBeTrue()
        ->and((string) $fetcher->getDocComment())->toContain('@internal')->not->toContain('@api');
});

/**
 * The default consent options with another consent text version.
 */
function consentOptionsWithVersion(?string $consentVersion): ConsentOptions
{
    $defaults = AuthorizeFlowTestCase::defaultConsentOptions();

    return new ConsentOptions(
        scopes: $defaults->scopes,
        roles: $defaults->roles,
        resources: $defaults->resources,
        resourcesRequired: $defaults->resourcesRequired,
        canGrant: true,
        consentVersion: $consentVersion,
    );
}

it('records the version and locale of the page the user saw, not those of the submission (Codex review of #59)', function (): void {
    $this->enableOAuth(consentOptionsWithVersion('2026-11'));
    app()->setLocale('it');
    $client = $this->createClient();
    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();

    app()->setLocale('de');
    $this->post('/oauth/authorize', ['auth_token' => $page->json('props.authToken'), 'scopes' => ['mcp:read'], 'role' => 'editor', 'resources' => ['news']])->assertRedirect();

    $decision = $this->grantStore()->replacedDecisions[0];
    $consentRecord = OAuthConsentRecord::query()->sole();

    expect($decision->locale)->toBe('it')
        ->and($decision->consentVersion)->toBe('2026-11')
        ->and($consentRecord->getAttribute('locale'))->toBe('it')
        ->and($consentRecord->getAttribute('consent_version'))->toBe('2026-11');
});

it('refuses an approval once the consent text changed after the page was shown (Codex review of #59)', function (): void {
    $this->enableOAuth(consentOptionsWithVersion('2026-11'));
    $client = $this->createClient();
    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();

    app()->instance(ConsentProvider::class, new FakeConsentProvider(consentOptionsWithVersion('2026-12')));
    $this->post('/oauth/authorize', ['auth_token' => $page->json('props.authToken'), 'scopes' => ['mcp:read'], 'role' => 'editor', 'resources' => ['news']])
        ->assertStatus(409);

    expect($this->grantStore()->replacedDecisions)->toBe([])
        ->and(OAuthConsentRecord::query()->count())->toBe(0)
        ->and(session()->has('authRequest'))->toBeFalse();
});

it('records the version and locale of the page the user saw on a denial (Codex review of #59)', function (): void {
    $this->enableOAuth(consentOptionsWithVersion('2026-11'));
    app()->setLocale('it');
    $client = $this->createClient();
    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();

    app()->setLocale('de');
    app()->instance(ConsentProvider::class, new FakeConsentProvider(consentOptionsWithVersion('2026-12')));
    $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')])->assertRedirect();

    $consentRecord = OAuthConsentRecord::query()->sole();

    expect($consentRecord->getAttribute('decision'))->toBe('denied')
        ->and($consentRecord->getAttribute('consent_version'))->toBe('2026-11')
        ->and($consentRecord->getAttribute('locale'))->toBe('it');
});

it('refuses a consent version or a locale longer than its column (Codex review of #59)', function (string $consentVersion, string $locale, string $message): void {
    $this->enableOAuth(consentOptionsWithVersion($consentVersion));
    app()->setLocale($locale);
    $client = $this->createClient();
    $this->withoutExceptionHandling();

    expect(fn () => $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true']))
        ->toThrow(LogicException::class, $message);
})->with([
    'a version of 33 characters' => [str_repeat('v', 33), 'en', 'The consent version must be at most 32 characters.'],
    'a locale of 17 characters' => ['2026-11', str_repeat('l', 17), 'The application locale must be at most 16 characters to be recorded with consent.'],
]);

it('records a consent version and a locale that fill their columns exactly', function (): void {
    $this->enableOAuth(consentOptionsWithVersion(str_repeat('v', 32)));
    app()->setLocale(str_repeat('l', 16));

    $this->obtainAuthorizationCode($this->createClient());

    expect(OAuthConsentRecord::query()->sole()->only(['consent_version', 'locale']))
        ->toBe(['consent_version' => str_repeat('v', 32), 'locale' => str_repeat('l', 16)]);
});

it('refuses a decision without the record of the rendered page, or with one for another page (Codex review of #59)', function (Closure $tamper): void {
    $this->enableOAuth();
    $client = $this->createClient();
    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();
    $tamper();

    $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')])->assertForbidden();

    expect(OAuthConsentRecord::query()->count())->toBe(0)
        ->and(session()->has('authRequest'))->toBeFalse();
})->with([
    'no record' => [static fn () => session()->forget(PendingAuthorizationRequestService::RENDERED_CONSENT_SESSION_KEY)],
    'a record for another page' => [static fn () => session()->put(PendingAuthorizationRequestService::RENDERED_CONSENT_SESSION_KEY.'.authToken', 'another-page')],
]);

it('forgets the rendered page once the decision is recorded', function (): void {
    $this->enableOAuth();
    $client = $this->createClient();
    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();

    $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')])->assertRedirect();

    expect(session()->has(PendingAuthorizationRequestService::RENDERED_CONSENT_SESSION_KEY))->toBeFalse();
});
