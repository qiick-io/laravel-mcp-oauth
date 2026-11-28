<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use Qiick\McpOAuth\AccessTokenAuthenticator;
use Qiick\McpOAuth\Actions\PruneAuthCodeExchangesAction;
use Qiick\McpOAuth\Actions\RevokeAuthCodeTokensAction;
use Qiick\McpOAuth\Actions\RevokeConnectedAppAction;
use Qiick\McpOAuth\Bridge\FamilyRevokingRefreshTokenRepository;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Contracts\InstallationGrantStoreContract;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\ConsentOption;
use Qiick\McpOAuth\Data\ConsentOptions;
use Qiick\McpOAuth\Data\GrantInstallationData;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\GrantReplacementData;
use Qiick\McpOAuth\Erasure\McpOAuthEraser;
use Qiick\McpOAuth\Events\McpConsentApprovedEvent;
use Qiick\McpOAuth\Events\McpConsentDeniedEvent;
use Qiick\McpOAuth\Events\McpGrantRevokedEvent;
use Qiick\McpOAuth\Events\McpRefreshTokenReusedEvent;
use Qiick\McpOAuth\Events\McpTokenRevokedEvent;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Testing\FakeAuditLogger;
use Qiick\McpOAuth\Testing\FakeConsentProvider;
use Qiick\McpOAuth\Testing\FakeGrantStore;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\HookedGrantStore;
use Qiick\McpOAuth\Tests\Support\TestUser;

uses(AuthorizeFlowTestCase::class);

const FIRST_INSTALLATION = 'edb06dcc-75b5-4af4-b08e-25393e025fa2';
const SECOND_INSTALLATION = 'f3add97d-af1e-4169-b778-65ad96ba090f';
const FIRST_INSTALLATION_THUMBPRINT = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2ai4EcM';
const FIRST_INSTALLATION_ORGANISATION = 'd86c20ee-59a8-4fac-a057-1ad7c6f88857';
const SECOND_INSTALLATION_ORGANISATION = '3840d961-0846-46de-9668-b077979ee5c5';

function createInstallationClient(AuthorizeFlowTestCase $testCase): Client
{
    $client = $testCase->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);

    return $client;
}

/** @return array{auth_token: string, scopes: list<string>, role: string, resources: list<string>} */
function installationApprovalFields(AuthorizeFlowTestCase $testCase, Client $client, TestUser $user, string $installId = FIRST_INSTALLATION): array
{
    $page = $testCase->actingAs($user)->get($testCase->authorizeUrl($client, [
        'install_id' => $installId,
        'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT,
    ]), ['X-Inertia' => 'true'])->assertOk()->assertJsonPath('props.isInstallationPairing', true);
    expect($page->json('props.options.notices'))->toContain('Pair this phone.');

    return [
        'auth_token' => $page->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ];
}

function approveInstallation(AuthorizeFlowTestCase $testCase, Client $client, TestUser $user, string $installId, ?string $organisation = null): string
{
    $approval = $testCase->post('/oauth/authorize', [
        ...installationApprovalFields($testCase, $client, $user, $installId),
        'organisation' => $organisation,
        'install_id' => 'discarded-form-value',
        'companion_jkt' => 'discarded-form-value',
    ])->assertRedirectContains('code=');
    parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirect);
    app('auth')->forgetGuards();
    $testCase->flushSession();

    return $redirect['code'];
}

it('refuses installation inputs from clients without trusted enrollment', function (array $installationParameters): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->get($this->authorizeUrl($this->createClient(), $installationParameters))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_request')->assertHeaderMissing('Location');
})->with([
    'install identifier only' => [['install_id' => FIRST_INSTALLATION]],
    'thumbprint only' => [['companion_jkt' => FIRST_INSTALLATION_THUMBPRINT]],
    'both values' => [['install_id' => FIRST_INSTALLATION, 'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT]],
]);

it('includes the pending installation in the consent denial audit', function (): void {
    $audit = new FakeAuditLogger;
    app()->instance(AuditLogger::class, $audit);
    Event::fake([McpConsentDeniedEvent::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);
    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client, [
        'install_id' => FIRST_INSTALLATION,
        'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT,
    ]), ['X-Inertia' => 'true'])->assertOk();
    $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')])->assertRedirectContains('error=access_denied');

    Event::assertDispatched(McpConsentDeniedEvent::class, fn (McpConsentDeniedEvent $event): bool => $event->installId === FIRST_INSTALLATION);
    expect($audit->entries[0]['event'])->toBe('oauth_consent_denied')
        ->and($audit->entries[0]['grantId'])->toBeNull()
        ->and($audit->entries[0]['properties']['install_id'])->toBe(FIRST_INSTALLATION);
});

it('preserves product options and notices on the installation consent page', function (): void {
    $options = AuthorizeFlowTestCase::defaultConsentOptions();
    $this->enableOAuth(new ConsentOptions(
        $options->scopes, $options->roles, $options->resources, $options->resourcesRequired, $options->canGrant,
        notices: ['Access applies to this organisation.'],
    ));
    McpOAuthRoutes::register();
    $client = createInstallationClient($this);

    $this->actingAs($this->createUser())->get($this->authorizeUrl($client, [
        'install_id' => FIRST_INSTALLATION,
        'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT,
    ]), ['X-Inertia' => 'true'])->assertOk()
        ->assertJsonPath('props.options.scopes.0.value', 'mcp:read')
        ->assertJsonPath('props.options.notices', ['Access applies to this organisation.', 'Pair this phone.']);
});

it('requires an installation id and a correctly encoded key thumbprint for flagged clients', function (array $installationParameters): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);

    $this->get($this->authorizeUrl($client, $installationParameters))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_request')->assertHeaderMissing('Location');
})->with([
    'neither field' => [[]],
    'missing thumbprint' => [['install_id' => FIRST_INSTALLATION]],
    'invalid UUID' => [['install_id' => 'install-one', 'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT]],
    'padded thumbprint' => [['install_id' => FIRST_INSTALLATION, 'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT.'=']],
    'array' => [['install_id' => [FIRST_INSTALLATION], 'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT]],
]);

it('refuses installation approval if the enrollment changes after the consent page', function (bool $isDuringConsent): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = createInstallationClient($this);
    $metadata = OAuthClientMetadata::query()->where('client_id', $client->getKey());
    $disableInstallation = static function () use ($metadata): void {
        $metadata->update(['has_per_install_grants' => false]);
    };
    $consentProvider = new FakeConsentProvider(
        AuthorizeFlowTestCase::defaultConsentOptions(),
        $isDuringConsent ? $disableInstallation : null,
    );
    app()->instance(ConsentProvider::class, $consentProvider);
    $approvalFields = installationApprovalFields($this, $client, $this->createUser());

    if (! $isDuringConsent) {
        $disableInstallation();
    }

    $this->post('/oauth/authorize', $approvalFields)->assertForbidden();
    expect($this->grantStore()->replacedDecisions)->toBe([])
        ->and($consentProvider->validatedDecisions)->toHaveCount($isDuringConsent ? 1 : 0);
})->with(['before approval' => false, 'during product validation' => true]);

it('refuses invalid installation replacements from the product before issuing a code', function (string $field, bool $isPreviousGrant): void {
    $this->enableOAuth();
    $store = Mockery::mock(InstallationGrantStoreContract::class);
    $store->shouldReceive('replaceForInstallation')->once()->andReturnUsing(static function (ConsentDecision $decision) use ($field, $isPreviousGrant): GrantReplacementData {
        $installation = $decision->installation;
        $fields = [
            'id' => 'new-grant',
            'clientId' => $decision->clientId,
            'userIdentifier' => $decision->userIdentifier,
            'revoked' => false,
            'scopes' => $decision->scopes,
            'authorizedAt' => now()->toDateTimeImmutable(),
            'lastUsedAt' => null,
            'installation' => $installation,
        ];
        $values = match ($field) {
            'id' => ['id' => 'new-grant'],
            'clientId', 'userIdentifier' => [$field => 'different-owner'],
            'revoked' => ['revoked' => true],
            'authorizedAt', 'installation' => [$field => null],
            'installation account' => ['installation' => new GrantInstallationData(SECOND_INSTALLATION, $installation->keyThumbprint)],
            'thumbprint' => ['installation' => new GrantInstallationData($installation->installId, str_repeat('A', 43))],
        };

        return $isPreviousGrant
            ? new GrantReplacementData(new GrantRecord(...$fields), new GrantRecord(...[...$fields, 'id' => 'prior-grant', ...$values]))
            : new GrantReplacementData(new GrantRecord(...[...$fields, ...$values]));
    });
    app()->instance(GrantStore::class, $store);
    McpOAuthRoutes::register();
    $approvalFields = installationApprovalFields($this, createInstallationClient($this), $this->createUser());
    $this->withoutExceptionHandling();

    expect(fn () => $this->post('/oauth/authorize', $approvalFields))
        ->toThrow(LogicException::class, $isPreviousGrant ? 'distinct previous grant' : 'authorized installation and consent time')
        ->and(Passport::authCode()->newQuery()->exists())->toBeFalse();
})->with([
    'current grant revoked' => ['revoked', false],
    'current grant client' => ['clientId', false],
    'current grant user' => ['userIdentifier', false],
    'current grant consent time' => ['authorizedAt', false],
    'current grant installation' => ['installation', false],
    'current grant account' => ['installation account', false],
    'current grant thumbprint' => ['thumbprint', false],
    'previous grant identity' => ['id', true],
    'previous grant client' => ['clientId', true],
    'previous grant user' => ['userIdentifier', true],
    'previous grant installation' => ['installation', true],
    'previous grant account' => ['installation account', true],
]);

it('requires the installation grant store contract before replacing a grant', function (): void {
    $this->enableOAuth();
    app()->instance(GrantStore::class, new HookedGrantStore($this->grantStore()));
    McpOAuthRoutes::register();
    $approvalFields = installationApprovalFields($this, createInstallationClient($this), $this->createUser());
    $this->withoutExceptionHandling();

    expect(fn () => $this->post('/oauth/authorize', $approvalFields))
        ->toThrow(LogicException::class, 'require InstallationGrantStoreContract');
});

it('takes the SQLite write lock before reading the installation during approval and revoke', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = createInstallationClient($this);
    $user = $this->createUser();
    $connection = OAuthClientMetadata::query()->getConnection();
    $statementsInTransaction = [];
    $connection->listen(static function (QueryExecuted $query) use ($connection, &$statementsInTransaction): void {
        if ($connection->transactionLevel() > 0 && str_contains($query->sql, 'oauth_client')) {
            $statementsInTransaction[] = $query->sql;
        }
    });

    approveInstallation($this, $client, $user, FIRST_INSTALLATION);

    $expectedLockStatement = $connection instanceof SQLiteConnection ? 'update ' : 'select ';
    expect($statementsInTransaction[0] ?? '')->toStartWith($expectedLockStatement)
        ->and(OAuthClientMetadata::isPerInstallClient((string) $client->getKey()))->toBeTrue();

    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update(['has_per_install_grants' => false]);
    $statementsInTransaction = [];
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getAuthIdentifier());
    app(RevokeConnectedAppAction::class)->execute($grant, $user);

    expect($statementsInTransaction[0] ?? '')->toStartWith($expectedLockStatement)
        ->and(OAuthClientMetadata::isPerInstallClient((string) $client->getKey()))->toBeFalse()
        ->and($this->grantStore()->find($grant->id)?->revoked)->toBeTrue();
});

it('retires only the pending code of the installation replaced by re-consent', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = createInstallationClient($this);
    $user = $this->createUser();
    $previousCode = approveInstallation($this, $client, $user, FIRST_INSTALLATION);
    $previousGrant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getAuthIdentifier());
    $previousCodeId = OAuthAuthCodeExchange::query()->where('grant_id', $previousGrant->id)->value('auth_code_id');
    $otherCode = approveInstallation($this, $client, $user, SECOND_INSTALLATION);
    $newCode = approveInstallation($this, $client, $user, FIRST_INSTALLATION);

    expect(Passport::authCode()->newQuery()->findOrFail($previousCodeId)->getAttribute('revoked'))->toBeTrue();
    $this->post('/oauth/token', $this->codeExchange($client, $previousCode))->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    $this->post('/oauth/token', $this->codeExchange($client, $otherCode))->assertOk();
    $this->post('/oauth/token', $this->codeExchange($client, $newCode))->assertOk();
});

it('rolls back an installation refresh revoke until its product grant was written', function (bool $hasWrittenGrant): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = createInstallationClient($this);
    $user = $this->createUser();
    $firstCode = approveInstallation($this, $client, $user, FIRST_INSTALLATION);
    $grantStore = $this->grantStore();
    $firstGrant = $grantStore->activeFor((string) $client->getKey(), (string) $user->getAuthIdentifier());
    $tokens = $this->post('/oauth/token', $this->codeExchange($client, $firstCode))->assertOk();
    approveInstallation($this, $client, $user, SECOND_INSTALLATION);
    $failure = static function (): never {
        throw new RuntimeException('Installation revoke did not complete.');
    };
    $hookedStore = new HookedGrantStore($grantStore);

    if ($hasWrittenGrant) {
        $hookedStore->afterNextRevoke = $failure;
    } else {
        $hookedStore->beforeRevoke = $failure;
    }

    app()->instance(GrantStore::class, $hookedStore);
    $response = $this->post('/oauth/revoke', ['client_id' => $client->getKey(), 'token' => $tokens->json('refresh_token')]);
    $response->assertStatus($hasWrittenGrant ? 200 : 500);
    expect($grantStore->find($firstGrant->id)?->revoked)->toBe($hasWrittenGrant)
        ->and(Passport::token()->newQuery()->where('revoked', false)->exists())->toBe(! $hasWrittenGrant)
        ->and(Passport::refreshToken()->newQuery()->exists())->toBe(! $hasWrittenGrant);
})->with(['before writing' => false, 'after a separate commit' => true]);

it('handles a deleted installation grant during revocation and refresh validation', function (): void {
    Event::fake([McpGrantRevokedEvent::class, McpRefreshTokenReusedEvent::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = createInstallationClient($this);
    $user = $this->createUser();
    $code = approveInstallation($this, $client, $user, FIRST_INSTALLATION);
    $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getAuthIdentifier());
    $refreshToken = Passport::refreshToken()->newQuery()->sole();

    // The product deleted its row after Connected apps read the grant.
    app()->instance(GrantStore::class, new FakeGrantStore);
    app(RevokeConnectedAppAction::class)->execute($grant, $user);
    Event::assertNotDispatched(McpGrantRevokedEvent::class);

    expect(app(FamilyRevokingRefreshTokenRepository::class)->isRefreshTokenRevoked($refreshToken->getKey()))->toBeTrue()
        ->and($refreshToken->refresh()->getAttribute('revoked'))->toBeTrue();
    Event::assertDispatched(McpRefreshTokenReusedEvent::class, fn (McpRefreshTokenReusedEvent $event): bool => $event->grantId === $grant->id
        && $event->installId === null);
});

it('pins codes and tokens to the consented installation and organisation', function (): void {
    $audit = new FakeAuditLogger;
    app()->instance(AuditLogger::class, $audit);
    Event::fake([McpConsentApprovedEvent::class, McpGrantRevokedEvent::class, McpTokenRevokedEvent::class]);
    $options = AuthorizeFlowTestCase::defaultConsentOptions();
    $this->enableOAuth(new ConsentOptions(
        $options->scopes, $options->roles, $options->resources, $options->resourcesRequired, $options->canGrant,
        organisations: [
            new ConsentOption(FIRST_INSTALLATION_ORGANISATION, 'First organisation', grantable: true),
            new ConsentOption(SECOND_INSTALLATION_ORGANISATION, 'Second organisation', grantable: true),
        ],
    ));
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);
    $user = $this->createUser();
    $firstCode = approveInstallation($this, $client, $user, strtoupper(FIRST_INSTALLATION), FIRST_INSTALLATION_ORGANISATION);
    $secondCode = approveInstallation($this, $client, $user, SECOND_INSTALLATION, FIRST_INSTALLATION_ORGANISATION);
    $otherOrganisationCode = approveInstallation($this, $client, $user, FIRST_INSTALLATION, SECOND_INSTALLATION_ORGANISATION);
    $authenticator = app(AccessTokenAuthenticator::class);
    $bearers = [];
    $grants = [];
    $refreshTokens = [];

    foreach ([
        [$firstCode, FIRST_INSTALLATION, FIRST_INSTALLATION_ORGANISATION],
        [$secondCode, SECOND_INSTALLATION, FIRST_INSTALLATION_ORGANISATION],
        [$otherOrganisationCode, FIRST_INSTALLATION, SECOND_INSTALLATION_ORGANISATION],
    ] as [$code, $installId, $organisation]) {
        $tokens = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
        $bearer = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$tokens->json('access_token')]);
        $grant = $authenticator->authenticate($bearer);
        expect($grant)->toBeInstanceOf(GrantRecord::class)
            ->and($grant->installation?->installId)->toBe($installId)
            ->and($grant->installation?->organisationId)->toBe($organisation)
            ->and($grant->installation?->keyThumbprint)->toBe(FIRST_INSTALLATION_THUMBPRINT)
            ->and($grant->authorizedAt)->not->toBeNull();
        $bearers[] = $bearer;
        $grants[] = $grant;
        $refreshTokens[] = $tokens->json('refresh_token');
    }

    approveInstallation($this, $client, $user, FIRST_INSTALLATION, FIRST_INSTALLATION_ORGANISATION);
    expect($authenticator->authenticate($bearers[0]))->not->toBeInstanceOf(GrantRecord::class)
        ->and($authenticator->authenticate($bearers[1]))->toBeInstanceOf(GrantRecord::class)
        ->and($authenticator->authenticate($bearers[2]))->toBeInstanceOf(GrantRecord::class);

    app(RevokeConnectedAppAction::class)->execute($grants[1], $user);
    expect($this->grantStore()->find($grants[1]->id)?->revoked)->toBeTrue()
        ->and($authenticator->authenticate($bearers[2]))->toBeInstanceOf(GrantRecord::class);

    $this->post('/oauth/revoke', ['client_id' => $client->getKey(), 'token' => $refreshTokens[2]])->assertOk();
    expect($this->grantStore()->find($grants[2]->id)?->revoked)->toBeTrue();
    Event::assertDispatched(McpConsentApprovedEvent::class, fn (McpConsentApprovedEvent $event): bool => $event->grantId === $grants[1]->id
        && $event->installId === SECOND_INSTALLATION);
    Event::assertDispatched(McpGrantRevokedEvent::class, fn (McpGrantRevokedEvent $event): bool => $event->grantId === $grants[1]->id
        && $event->installId === SECOND_INSTALLATION);
    Event::assertDispatched(McpTokenRevokedEvent::class, fn (McpTokenRevokedEvent $event): bool => $event->grantId === $grants[2]->id
        && $event->installId === FIRST_INSTALLATION);
    expect(array_column(array_column($audit->entries, 'properties'), 'install_id'))
        ->toBe([FIRST_INSTALLATION, SECOND_INSTALLATION, FIRST_INSTALLATION, FIRST_INSTALLATION, SECOND_INSTALLATION, FIRST_INSTALLATION]);
});

it('revokes the grant at the absolute installation age even after rotation', function (?int $configuredAge, int $age, string $attempt): void {
    $audit = new FakeAuditLogger;
    app()->instance(AuditLogger::class, $audit);
    Event::fake([McpGrantRevokedEvent::class, McpRefreshTokenReusedEvent::class]);
    $this->enableOAuth();

    if ($configuredAge !== null) {
        config()->set('mcp-oauth.companion.grant_max_age_days', $configuredAge);
    }

    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);
    $user = $this->createUser();
    $code = approveInstallation($this, $client, $user, FIRST_INSTALLATION);
    $issued = $this->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getAuthIdentifier());
    $consentedAt = $grant?->authorizedAt;
    expect($consentedAt)->toBeInstanceOf(DateTimeImmutable::class);
    $expiresAt = $consentedAt->add(new DateInterval("P{$age}D"));
    $this->travelTo($expiresAt->sub(new DateInterval('PT1S')));
    $parameters = [
        'grant_type' => 'refresh_token',
        'client_id' => $client->getKey(),
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ];
    $rotated = $this->post('/oauth/token', [...$parameters, 'refresh_token' => $issued->json('refresh_token')])->assertOk();
    $this->travelTo($expiresAt);

    $bearer = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$rotated->json('access_token')]);

    if ($attempt === 'bearer') {
        expect(app(AccessTokenAuthenticator::class)->authenticate($bearer))->not->toBeInstanceOf(GrantRecord::class)
            ->and($this->grantStore()->find($grant->id)?->revoked)->toBeTrue();
    } elseif ($attempt === 'refresh validation') {
        $refreshTokenId = Passport::refreshToken()->newQuery()->where('revoked', false)->sole()->getKey();
        expect(app(FamilyRevokingRefreshTokenRepository::class)->isRefreshTokenRevoked($refreshTokenId))->toBeTrue()
            ->and($this->grantStore()->find($grant->id)?->revoked)->toBeTrue();
    } elseif ($attempt === 'rotation') {
        // Rotation can reach its compare-and-set after the earlier active check.
        $refreshTokenId = Passport::refreshToken()->newQuery()->where('revoked', false)->sole()->getKey();
        expect(fn () => app(FamilyRevokingRefreshTokenRepository::class)->revokeRefreshToken($refreshTokenId))
            ->toThrow(OAuthServerException::class)
            ->and($this->grantStore()->find($grant->id)?->revoked)->toBeTrue();
    }

    $this->post('/oauth/token', [...$parameters, 'refresh_token' => $rotated->json('refresh_token')])
        ->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    $revokedGrant = $this->grantStore()->find($grant->id);
    expect(app(AccessTokenAuthenticator::class)->authenticate($bearer))->not->toBeInstanceOf(GrantRecord::class)
        ->and($revokedGrant?->authorizedAt)->toEqual($consentedAt)
        ->and($revokedGrant?->revocationReason?->value)->toBe('expired')
        ->and(Passport::token()->newQuery()->where('revoked', false)->exists())->toBeFalse()
        ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->exists())->toBeFalse();
    Event::assertDispatchedTimes(McpGrantRevokedEvent::class, 1);
    Event::assertDispatched(McpGrantRevokedEvent::class, fn (McpGrantRevokedEvent $event): bool => $event->grantId === $grant->id
        && $event->installId === FIRST_INSTALLATION
        && $event->reason->value === 'expired');
    expect($audit->entries[1]['properties'])->toMatchArray(['install_id' => FIRST_INSTALLATION, 'reason' => 'expired']);
    $this->post('/oauth/token', [...$parameters, 'refresh_token' => $rotated->json('refresh_token')])
        ->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    Event::assertNotDispatched(McpRefreshTokenReusedEvent::class);
    expect($audit->entries)->toHaveCount(2);
})->with([
    'refresh at the shipped default' => [null, 180, 'refresh'],
    'bearer at a configured age' => [7, 7, 'bearer'],
    'deadline reached at refresh validation' => [7, 7, 'refresh validation'],
    'deadline reached during rotation' => [7, 7, 'rotation'],
]);

it('revokes only the exchanged installation grant when a credential is replayed', function (bool $usesRefreshToken, int $revokedTokenCount): void {
    Event::fake([McpRefreshTokenReusedEvent::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);
    $user = $this->createUser();
    $first = $this->codeExchange($client, approveInstallation($this, $client, $user, FIRST_INSTALLATION));
    $second = $this->codeExchange($client, approveInstallation($this, $client, $user, SECOND_INSTALLATION));
    $firstTokens = $this->post('/oauth/token', $first)->assertOk();
    $secondTokens = $this->post('/oauth/token', $second)->assertOk();

    if ($usesRefreshToken) {
        $refresh = [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'resource' => AuthorizeFlowTestCase::RESOURCE,
            'refresh_token' => $firstTokens->json('refresh_token'),
        ];
        $this->post('/oauth/token', $refresh)->assertOk();
        $this->post('/oauth/token', $refresh)->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
        Event::assertDispatched(McpRefreshTokenReusedEvent::class, fn (McpRefreshTokenReusedEvent $event): bool => $event->installId === FIRST_INSTALLATION);
    } else {
        $this->post('/oauth/token', $first)->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    }

    $bearer = Request::create('/mcp', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$secondTokens->json('access_token')]);
    $grant = app(AccessTokenAuthenticator::class)->authenticate($bearer);
    expect($grant)->toBeInstanceOf(GrantRecord::class)
        ->and($grant->installation?->installId)->toBe(SECOND_INSTALLATION)
        ->and(Passport::token()->newQuery()->where('revoked', true)->count())->toBe($revokedTokenCount);
})->with(['authorization code' => [false, 1], 'refresh token' => [true, 2]]);

it('never falls back to another installation when the code has no valid grant binding', function (string $problem): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);
    $user = $this->createUser();
    $code = approveInstallation($this, $client, $user, FIRST_INSTALLATION);
    $exchange = OAuthAuthCodeExchange::query()->sole();

    if ($problem === 'missing binding') {
        $exchange->delete();
    } else {
        $exchange->update(['grant_id' => SECOND_INSTALLATION]);
    }

    $this->post('/oauth/token', $this->codeExchange($client, $code))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_grant');
    expect(Passport::token()->newQuery()->exists())->toBeFalse();
})->with(['missing binding', 'missing grant']);

it('prunes a pending code when it expires without revoking the installation grant', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);
    approveInstallation($this, $client, $this->createUser(), FIRST_INSTALLATION);
    $exchange = OAuthAuthCodeExchange::query()->sole();
    $this->travelTo($exchange->expires_at->copy()->addSecond());

    app(RevokeAuthCodeTokensAction::class)->execute($exchange->auth_code_id);
    expect($this->grantStore()->find($exchange->grant_id)?->revoked)->toBeFalse()
        ->and(app(PruneAuthCodeExchangesAction::class)->execute(false))->toBe(1)
        ->and(OAuthAuthCodeExchange::query()->exists())->toBeFalse();
});

it('erases pending and exchanged credentials for all subject installations', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);
    $subject = $this->createUser();
    $anotherUser = $this->createUser();
    $consumedCode = approveInstallation($this, $client, $subject, FIRST_INSTALLATION);
    approveInstallation($this, $client, $subject, SECOND_INSTALLATION);
    OAuthAuthCodeExchange::query()->create([
        'auth_code_id' => str_repeat('a', 80),
        'grant_id' => SECOND_INSTALLATION,
        'user_identifier' => (string) $anotherUser->getAuthIdentifier(),
        'expires_at' => now()->addMinute(),
    ]);
    $this->post('/oauth/token', $this->codeExchange($client, $consumedCode))->assertOk();
    expect(OAuthAuthCodeExchange::query()->count())->toBe(3);

    $report = app(McpOAuthEraser::class)->erase(
        (string) $subject->getAuthIdentifier(), FIRST_INSTALLATION_ORGANISATION, McpOAuthEraser::DELETE,
    );

    expect($report->stores['oauth_auth_code_exchanges']['deleted'])->toBe(2)
        ->and(OAuthAuthCodeExchange::query()->sole()->user_identifier)->toBe((string) $anotherUser->getAuthIdentifier())
        ->and(Passport::token()->newQuery()->exists())->toBeFalse()
        ->and(Passport::refreshToken()->newQuery()->exists())->toBeFalse()
        ->and(Passport::authCode()->newQuery()->exists())->toBeFalse();
});
