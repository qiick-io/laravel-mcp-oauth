<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpRevokedRecordsPurged;
use Qiick\McpOAuth\Events\McpUnusedClientsPruned;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\HookedGrantStore;

uses(AuthorizeFlowTestCase::class);

/**
 * Retention (standards review M5, decisions of 2026-11-22): revoked clients,
 * revoked grants and consent evidence go 90 days after revocation, never
 * earlier; never-authorised DCR clients go after 24 hours; `mcp-oauth:check`
 * reports readiness.
 */
beforeEach(function (): void {
    $this->travelTo(now()->startOfMinute());
});

/**
 * A DCR client revoked the given number of days ago, with one token and code.
 */
function clientRevokedDaysAgo(AuthorizeFlowTestCase $testCase, int $days): Client
{
    $client = $testCase->createClient(isRevoked: true);
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update(['revoked_at' => now()->subDays($days)]);
    DB::table('oauth_access_tokens')->insert([
        'id' => 'token-'.$client->getKey(), 'user_id' => 1, 'client_id' => $client->getKey(), 'name' => null,
        'scopes' => '[]', 'revoked' => true, 'created_at' => now(), 'updated_at' => now(), 'expires_at' => now()->addDay(),
    ]);
    DB::table('oauth_refresh_tokens')->insert([
        'id' => 'refresh-'.$client->getKey(), 'access_token_id' => 'token-'.$client->getKey(), 'revoked' => true, 'expires_at' => now()->addDay(),
    ]);
    DB::table('oauth_auth_codes')->insert([
        'id' => 'code-'.$client->getKey(), 'user_id' => 1, 'client_id' => $client->getKey(),
        'scopes' => '[]', 'revoked' => true, 'expires_at' => now()->addMinutes(10),
    ]);

    return $client;
}

function grantRevokedDaysAgo(AuthorizeFlowTestCase $testCase, int $days): GrantRecord
{
    $grant = new GrantRecord(
        id: (string) Str::uuid7(),
        clientId: (string) Str::uuid7(),
        userIdentifier: '1',
        revoked: false,
        scopes: ['mcp:read'],
        authorizedAt: null,
        lastUsedAt: null,
    );
    $testCase->grantStore()->seed($grant);
    $testCase->travel(-$days)->days();
    $testCase->grantStore()->revoke($grant->id, null, RevocationReason::User);
    $testCase->travel($days)->days();

    return $grant;
}

function consentRecord(array $attributes): OAuthConsentRecord
{
    return OAuthConsentRecord::query()->create([
        'client_id' => (string) Str::uuid7(),
        'user_identifier' => '1',
        'decision' => 'approved',
        'redirect_uri' => 'https://app.example/callback',
        'redirect_host' => 'app.example',
        'requested_scopes' => ['mcp:use'],
        ...$attributes,
    ]);
}

// --- mcp-oauth:purge-revoked ----------------------------------------------------

it('purges a revoked client only once 90 full days have passed', function (int $days, bool $isPurged): void {
    $this->enableOAuth();
    $client = clientRevokedDaysAgo($this, $days);

    $this->artisan('mcp-oauth:purge-revoked')->assertSuccessful();

    expect(Client::query()->whereKey($client->getKey())->exists())->toBe(! $isPurged)
        ->and(OAuthClientMetadata::query()->where('client_id', $client->getKey())->exists())->toBe(! $isPurged)
        ->and(DB::table('oauth_access_tokens')->where('client_id', $client->getKey())->exists())->toBe(! $isPurged)
        ->and(DB::table('oauth_refresh_tokens')->where('id', 'refresh-'.$client->getKey())->exists())->toBe(! $isPurged)
        ->and(DB::table('oauth_auth_codes')->where('client_id', $client->getKey())->exists())->toBe(! $isPurged);
})->with([
    '89 days' => [89, false],
    '90 days' => [90, false],
    '91 days' => [91, true],
]);

it('asks the product to purge its grants revoked more than 90 days ago', function (int $days, bool $isPurged): void {
    $this->enableOAuth();
    $grant = grantRevokedDaysAgo($this, $days);

    $this->artisan('mcp-oauth:purge-revoked')->assertSuccessful();

    expect($this->grantStore()->find($grant->id) === null)->toBe($isPurged);
})->with([
    '89 days' => [89, false],
    '90 days' => [90, false],
    '91 days' => [91, true],
]);

it('purges consent evidence past its retention and starts the clock for a grant no longer active', function (): void {
    $this->enableOAuth();
    $activeGrant = grantRevokedDaysAgo($this, 0);
    $this->grantStore()->seed($liveGrant = new GrantRecord(
        id: (string) Str::uuid7(), clientId: (string) Str::uuid7(), userIdentifier: '1',
        revoked: false, scopes: ['mcp:read'], authorizedAt: null, lastUsedAt: null,
    ));
    $expiredDenial = consentRecord(['decision' => 'denied', 'retention_until' => now()->subDay()]);
    $keptDenial = consentRecord(['decision' => 'denied', 'retention_until' => now()->addDay()]);
    $liveApproval = consentRecord(['grant_id' => $liveGrant->id]);
    $revokedApproval = consentRecord(['grant_id' => $activeGrant->id]);
    $orphanApproval = consentRecord(['grant_id' => (string) Str::uuid7()]);

    $this->artisan('mcp-oauth:purge-revoked')->assertSuccessful();

    expect(OAuthConsentRecord::query()->whereKey($expiredDenial->getKey())->exists())->toBeFalse()
        ->and(OAuthConsentRecord::query()->whereKey($keptDenial->getKey())->exists())->toBeTrue()
        ->and(OAuthConsentRecord::query()->find($liveApproval->getKey())?->retention_until)->toBeNull()
        ->and(OAuthConsentRecord::query()->find($revokedApproval->getKey())?->retention_until?->toIso8601String())->toBe(now()->addDays(90)->toIso8601String())
        ->and(OAuthConsentRecord::query()->find($orphanApproval->getKey())?->retention_until?->toIso8601String())->toBe(now()->addDays(90)->toIso8601String());
});

it('never purges a Passport client the package did not register', function (): void {
    $this->enableOAuth();
    $productClient = clientRevokedDaysAgo($this, 200);
    OAuthClientMetadata::query()->where('client_id', $productClient->getKey())->delete();

    $this->artisan('mcp-oauth:purge-revoked')->assertSuccessful();

    expect(Client::query()->whereKey($productClient->getKey())->exists())->toBeTrue();
});

it('reports the purge and dispatches McpRevokedRecordsPurged', function (): void {
    Event::fake([McpRevokedRecordsPurged::class]);
    $this->enableOAuth();
    clientRevokedDaysAgo($this, 91);
    grantRevokedDaysAgo($this, 91);
    consentRecord(['decision' => 'denied', 'retention_until' => now()->subDay()]);

    $this->artisan('mcp-oauth:purge-revoked')
        ->expectsOutput('Purged 1 clients, 1 grants and 1 consent records revoked before '.now()->subDays(90)->toIso8601String().'.')
        ->assertSuccessful();

    Event::assertDispatched(McpRevokedRecordsPurged::class, static fn (McpRevokedRecordsPurged $event): bool => $event->clientCount === 1
        && $event->grantCount === 1
        && $event->consentRecordCount === 1
        && $event->cutoffIso8601 === now()->subDays(90)->toIso8601String());
});

it('only counts with --dry-run, and leaves the product grants alone', function (): void {
    Event::fake([McpRevokedRecordsPurged::class]);
    $this->enableOAuth();
    $client = clientRevokedDaysAgo($this, 91);
    $grant = grantRevokedDaysAgo($this, 91);
    $denial = consentRecord(['decision' => 'denied', 'retention_until' => now()->subDay()]);

    $this->artisan('mcp-oauth:purge-revoked', ['--dry-run' => true])
        ->expectsOutput('Would purge 1 clients and 1 consent records revoked before '.now()->subDays(90)->toIso8601String().'; product grants are purged only for real.')
        ->assertSuccessful();

    expect(Client::query()->whereKey($client->getKey())->exists())->toBeTrue()
        ->and($this->grantStore()->find($grant->id))->not->toBeNull()
        ->and(OAuthConsentRecord::query()->whereKey($denial->getKey())->exists())->toBeTrue();
    Event::assertNotDispatched(McpRevokedRecordsPurged::class);
});

it('follows revoked_retention_days', function (): void {
    $this->enableOAuth();
    config()->set('mcp-oauth.revoked_retention_days', 30);
    $client = clientRevokedDaysAgo($this, 31);

    $this->artisan('mcp-oauth:purge-revoked')->assertSuccessful();

    expect(Client::query()->whereKey($client->getKey())->exists())->toBeFalse();
});

// --- mcp-oauth:prune-unused-clients ---------------------------------------------

/**
 * A DCR client registered the given number of hours ago.
 */
function clientRegisteredHoursAgo(AuthorizeFlowTestCase $testCase, int $hours): Client
{
    $client = $testCase->createClient();
    $client->forceFill(['created_at' => now()->subHours($hours)])->save();

    return $client;
}

it('prunes DCR clients never authorised after 24 hours, and nothing else', function (): void {
    Event::fake([McpUnusedClientsPruned::class]);
    $this->enableOAuth();
    $unused = clientRegisteredHoursAgo($this, 25);
    $fresh = clientRegisteredHoursAgo($this, 23);
    $authorised = clientRegisteredHoursAgo($this, 25);
    $this->grantStore()->seed(new GrantRecord(
        id: (string) Str::uuid7(), clientId: (string) $authorised->getKey(), userIdentifier: '1',
        revoked: true, scopes: ['mcp:read'], authorizedAt: null, lastUsedAt: null,
    ));
    $inRetention = clientRegisteredHoursAgo($this, 25);
    OAuthClientMetadata::query()->where('client_id', $inRetention->getKey())->update(['revoked_at' => now()->subDay()]);
    $productClient = clientRegisteredHoursAgo($this, 25);
    OAuthClientMetadata::query()->where('client_id', $productClient->getKey())->delete();

    $this->artisan('mcp-oauth:prune-unused-clients')
        ->expectsOutput('Pruned 1 unused clients registered before '.now()->subHours(24)->toIso8601String().'.')
        ->assertSuccessful();

    expect(Client::query()->whereKey($unused->getKey())->exists())->toBeFalse()
        ->and(OAuthClientMetadata::query()->where('client_id', $unused->getKey())->exists())->toBeFalse()
        ->and(Client::query()->whereKey([$fresh->getKey(), $authorised->getKey(), $inRetention->getKey(), $productClient->getKey()])->count())->toBe(4);
    Event::assertDispatched(McpUnusedClientsPruned::class, static fn (McpUnusedClientsPruned $event): bool => $event->count === 1
        && $event->cutoffIso8601 === now()->subHours(24)->toIso8601String());
});

it('keeps a client the boundary has not passed: 23 and 24 hours kept, 25 pruned', function (int $hours, bool $isPruned): void {
    $this->enableOAuth();
    $client = clientRegisteredHoursAgo($this, $hours);

    $this->artisan('mcp-oauth:prune-unused-clients')->assertSuccessful();

    expect(Client::query()->whereKey($client->getKey())->exists())->toBe(! $isPruned);
})->with([
    '23 hours' => [23, false],
    '24 hours' => [24, false],
    '25 hours' => [25, true],
]);

it('never prunes a client a user once authorised, after its revoked grant is purged (#31 review B1)', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    ['user' => $user] = $this->obtainAuthorizationCode($client);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());
    $this->grantStore()->revoke($grant->id, (string) $user->getKey(), RevocationReason::User);

    $this->travel(91)->days();
    $this->artisan('mcp-oauth:purge-revoked')->assertSuccessful();

    expect($this->grantStore()->find($grant->id))->toBeNull();

    $this->artisan('mcp-oauth:prune-unused-clients')->assertSuccessful();

    expect(Client::query()->whereKey($client->getKey())->exists())->toBeTrue();
});

it('marks a client authorised at its first approval and keeps that date on re-consent', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    $firstAuthorizedAt = fn (): mixed => OAuthClientMetadata::query()->where('client_id', $client->getKey())->value('first_authorized_at');

    expect($firstAuthorizedAt())->toBeNull();

    ['user' => $user] = $this->obtainAuthorizationCode($client);
    $firstApproval = $firstAuthorizedAt();
    $this->travel(1)->days();
    $this->obtainAuthorizationCode($client, $user);

    expect($firstApproval)->not->toBeNull()
        ->and($firstAuthorizedAt())->toEqual($firstApproval);
});

it('only counts unused clients with --dry-run', function (): void {
    Event::fake([McpUnusedClientsPruned::class]);
    $this->enableOAuth();
    $unused = clientRegisteredHoursAgo($this, 25);

    $this->artisan('mcp-oauth:prune-unused-clients', ['--dry-run' => true])
        ->expectsOutput('Would prune 1 unused clients registered before '.now()->subHours(24)->toIso8601String().'.')
        ->assertSuccessful();

    expect(Client::query()->whereKey($unused->getKey())->exists())->toBeTrue();
    Event::assertNotDispatched(McpUnusedClientsPruned::class);
});

it('keeps a client authorised or put in retention after the prune selected it (#31 review M1)', function (string $change): void {
    $this->enableOAuth();
    $hookedGrantStore = new HookedGrantStore($this->grantStore());
    app()->instance(GrantStore::class, $hookedGrantStore);
    $client = clientRegisteredHoursAgo($this, 25);
    $unusedClient = clientRegisteredHoursAgo($this, 25);
    // A user approves the client (or an admin blocks it) once the prune has read it as unused.
    $hookedGrantStore->afterNextEverAuthorized = static fn () => OAuthClientMetadata::query()
        ->where('client_id', $client->getKey())
        ->update([$change => now()]);

    $this->artisan('mcp-oauth:prune-unused-clients')
        ->expectsOutput('Pruned 1 unused clients registered before '.now()->subHours(24)->toIso8601String().'.')
        ->assertSuccessful();

    expect(Client::query()->whereKey($client->getKey())->exists())->toBeTrue()
        ->and(Client::query()->whereKey($unusedClient->getKey())->exists())->toBeFalse();
})->with(['first_authorized_at', 'revoked_at']);

it('prunes unused clients across more than one chunk of 100', function (): void {
    $this->enableOAuth();
    $hookedGrantStore = new HookedGrantStore($this->grantStore());
    app()->instance(GrantStore::class, $hookedGrantStore);

    foreach (range(1, 120) as $clientNumber) {
        clientRegisteredHoursAgo($this, 25);
    }

    $this->artisan('mcp-oauth:prune-unused-clients')
        ->expectsOutput('Pruned 120 unused clients registered before '.now()->subHours(24)->toIso8601String().'.')
        ->assertSuccessful();

    // One everAuthorized() question per chunk, never the whole table at once.
    expect(Client::query()->count())->toBe(0)
        ->and($hookedGrantStore->everAuthorizedBatchSizes)->toBe([100, 20]);
});

// --- mcp-oauth:check --------------------------------------------------------------

it('reports OAuth off as a healthy state', function (): void {
    config()->set('mcp-oauth.enabled', false);

    $this->artisan('mcp-oauth:check')
        ->expectsOutputToContain('OAuth: off')
        ->assertSuccessful();
});

it('reports a ready server with its issuer, resource and key source', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->artisan('mcp-oauth:check')
        ->expectsOutputToContain('OAuth: on')
        ->expectsOutputToContain('Issuer: https://mcp-oauth.test')
        ->expectsOutputToContain('Resource: https://mcp-oauth.test/mcp')
        ->expectsOutputToContain('Passport keys: env, usable')
        ->expectsOutputToContain('Foreign Passport routes: none')
        ->assertSuccessful();
});

it('fails when OAuth is on but the Passport keys are missing', function (): void {
    $this->enableOAuth();
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    $missingKeyDirectory = sys_get_temp_dir().'/mcp-oauth-check-no-keys-'.uniqid('', true);
    mkdir($missingKeyDirectory, 0700);
    Passport::loadKeysFrom($missingKeyDirectory);

    $this->artisan('mcp-oauth:check')
        ->expectsOutputToContain('Passport keys: file, missing or unusable')
        ->assertFailed();
});

it('fails beside a foreign Passport route (design §3.3)', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    Route::get('oauth/device', static fn (): string => 'device')->name('passport.device');

    $this->artisan('mcp-oauth:check')
        ->expectsOutputToContain('Foreign Passport routes: passport.device')
        ->assertFailed();
});

it('reports an incomplete env key pair as env keys that are not usable', function (): void {
    $this->enableOAuth();
    config()->set('passport.private_key', '');

    $this->artisan('mcp-oauth:check')
        ->expectsOutputToContain('Passport keys: env, missing or unusable')
        ->assertFailed();
});
