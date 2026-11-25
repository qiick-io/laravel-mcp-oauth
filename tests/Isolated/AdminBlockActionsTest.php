<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Actions\BlockClientAction;
use Qiick\McpOAuth\Actions\BlockRedirectHostAction;
use Qiick\McpOAuth\Actions\BulkBlockClientsAction;
use Qiick\McpOAuth\Actions\UnblockRedirectHostAction;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpClientBlocked;
use Qiick\McpOAuth\Events\McpRedirectHostBlocked;
use Qiick\McpOAuth\Events\McpRedirectHostUnblocked;
use Qiick\McpOAuth\McpOAuthAdminRoutes;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\TestUser;

uses(AuthorizeFlowTestCase::class);

const UNKNOWN_CLIENT_ID = '0195f0a0-0000-7000-8000-00000000dead';

/**
 * Admin block actions (design §5.2, §8.2; S39, S40): blocking a client
 * revokes it and every credential it holds in one transaction; blocking a
 * host writes the row, then blocks each matching client in chunks.
 */

/**
 * A client with a live grant, access token, refresh token and an unused
 * auth code, through the real consent and token endpoints.
 *
 * @return array{client: Client, user: TestUser}
 */
function clientWithCredentials(AuthorizeFlowTestCase $testCase, string $redirectUri = AuthorizeFlowTestCase::REGISTERED_REDIRECT_URI): array
{
    $client = $testCase->createClient([$redirectUri]);
    ['code' => $code, 'user' => $user] = $testCase->obtainAuthorizationCode($client);
    $testCase->withHeaders(['Accept' => 'application/json'])
        ->post('/oauth/token', $testCase->codeExchange($client, $code))
        ->assertOk();
    // A second, unexchanged code.
    $testCase->obtainAuthorizationCode($client, $user);

    return ['client' => $client, 'user' => $user];
}

function isClientFullyRevoked(Client $client): bool
{
    $clientId = (string) $client->getKey();
    $accessTokenIds = DB::table('oauth_access_tokens')->where('client_id', $clientId)->pluck('id');

    return (bool) Passport::client()->newQuery()->whereKey($clientId)->value('revoked')
        && $accessTokenIds->isNotEmpty()
        && DB::table('oauth_access_tokens')->where('client_id', $clientId)->where('revoked', false)->doesntExist()
        && DB::table('oauth_refresh_tokens')->whereIn('access_token_id', $accessTokenIds)->where('revoked', false)->doesntExist()
        && DB::table('oauth_auth_codes')->where('client_id', $clientId)->where('revoked', false)->doesntExist();
}

beforeEach(function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
});

it('blocks a client: revokes it, its grants, tokens and codes, and marks its metadata', function (): void {
    Event::fake([McpClientBlocked::class]);
    ['client' => $client, 'user' => $user] = clientWithCredentials($this);
    ['client' => $otherClient] = clientWithCredentials($this);
    $admin = $this->createUser();

    app(BlockClientAction::class)->execute($client, $admin);

    $metadata = OAuthClientMetadata::query()->where('client_id', $client->getKey())->sole();

    expect(isClientFullyRevoked($client))->toBeTrue()
        ->and(DB::table('oauth_access_tokens')->where('client_id', $otherClient->getKey())->where('revoked', false)->exists())->toBeTrue()
        ->and($this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey()))->toBeNull()
        ->and(collect($this->grantStore()->revocations)->pluck('reason')->unique()->all())->toBe([RevocationReason::Admin])
        ->and($metadata->revoked_at)->not->toBeNull()
        ->and($metadata->revocation_reason)->toBe('admin');

    Event::assertDispatched(McpClientBlocked::class, static fn (McpClientBlocked $event): bool => $event->clientId === (string) $client->getKey()
        && $event->actorIdentifier === (string) $admin->getKey());
});

it('bulk blocks each listed client and ignores unknown or already revoked ones (S40)', function (): void {
    Event::fake([McpClientBlocked::class]);
    ['client' => $firstClient] = clientWithCredentials($this);
    ['client' => $secondClient] = clientWithCredentials($this);
    ['client' => $untouchedClient] = clientWithCredentials($this);
    $revokedClient = $this->createClient(isRevoked: true);

    app(BulkBlockClientsAction::class)->execute(
        [(string) $firstClient->getKey(), (string) $secondClient->getKey(), (string) $revokedClient->getKey(), (string) Str::uuid7()],
        null,
    );

    expect(isClientFullyRevoked($firstClient))->toBeTrue()
        ->and(isClientFullyRevoked($secondClient))->toBeTrue()
        ->and(DB::table('oauth_access_tokens')->where('client_id', $untouchedClient->getKey())->where('revoked', false)->exists())->toBeTrue();

    Event::assertDispatchedTimes(McpClientBlocked::class, 2);
});

it('blocks a host and its subdomains, normalised to ASCII, and blocks the clients that redirect there', function (): void {
    Event::fake([McpRedirectHostBlocked::class, McpClientBlocked::class]);
    ['client' => $hostClient] = clientWithCredentials($this, 'https://xn--bcher-kva.example/callback');
    ['client' => $subdomainClient] = clientWithCredentials($this, 'https://app.xn--bcher-kva.example/callback');
    ['client' => $otherClient] = clientWithCredentials($this, 'https://other.example/callback');
    $admin = $this->createUser();

    $blockedHost = app(BlockRedirectHostAction::class)->execute('Bücher.example', $admin, isSubdomainMatched: true, reason: 'Phishing');

    expect($blockedHost->host)->toBe('xn--bcher-kva.example')
        ->and($blockedHost->getAttribute('host_original'))->toBe('Bücher.example')
        ->and($blockedHost->match_mode)->toBe('host_and_subdomains')
        ->and($blockedHost->getAttribute('reason'))->toBe('Phishing')
        ->and($blockedHost->getAttribute('created_by'))->toBe($admin->getKey())
        ->and(isClientFullyRevoked($hostClient))->toBeTrue()
        ->and(isClientFullyRevoked($subdomainClient))->toBeTrue()
        ->and(Passport::client()->newQuery()->whereKey($otherClient->getKey())->value('revoked'))->toBeFalsy();

    Event::assertDispatched(McpRedirectHostBlocked::class, static fn (McpRedirectHostBlocked $event): bool => $event->host === 'xn--bcher-kva.example'
        && $event->actorIdentifier === (string) $admin->getKey());
});

it('blocks only the host itself in exact mode, and once however often it is blocked', function (): void {
    ['client' => $hostClient] = clientWithCredentials($this, 'https://app.example/callback');
    ['client' => $subdomainClient] = clientWithCredentials($this, 'https://login.app.example/callback');

    app(BlockRedirectHostAction::class)->execute('app.example', null, isSubdomainMatched: false);
    app(BlockRedirectHostAction::class)->execute('app.example.', null, isSubdomainMatched: false);

    expect(OAuthBlockedRedirectHost::query()->where('host', 'app.example')->sole()->match_mode)->toBe('exact')
        ->and(isClientFullyRevoked($hostClient))->toBeTrue()
        ->and(Passport::client()->newQuery()->whereKey($subdomainClient->getKey())->value('revoked'))->toBeFalsy();
});

it('blocks every matching client across more than one chunk (S39)', function (): void {
    config()->set('mcp-oauth.host_block_chunk_size', 2);
    $matchingClients = array_map(fn (): Client => $this->createClient(['https://app.example/callback']), range(1, 5));
    $otherClient = $this->createClient(['https://other.example/callback']);

    app(BlockRedirectHostAction::class)->execute('app.example', null, isSubdomainMatched: true);

    foreach ($matchingClients as $matchingClient) {
        expect(Passport::client()->newQuery()->whereKey($matchingClient->getKey())->value('revoked'))->toBeTruthy();
    }

    expect(Passport::client()->newQuery()->whereKey($otherClient->getKey())->value('revoked'))->toBeFalsy();
});

it('refuses a host that does not normalise', function (string $host): void {
    expect(fn () => app(BlockRedirectHostAction::class)->execute($host, null, isSubdomainMatched: true))
        ->toThrow(InvalidArgumentException::class);

    expect(OAuthBlockedRedirectHost::query()->count())->toBe(0);
})->with([
    'empty' => [' '],
    'an underscore' => ['bad_host.example'],
]);

it('unblocks a host: the row goes, revoked clients stay revoked', function (): void {
    Event::fake([McpRedirectHostUnblocked::class]);
    ['client' => $hostClient] = clientWithCredentials($this, 'https://app.example/callback');
    $blockedHost = app(BlockRedirectHostAction::class)->execute('app.example', null, isSubdomainMatched: true);
    $admin = $this->createUser();

    app(UnblockRedirectHostAction::class)->execute($blockedHost, $admin);

    expect(OAuthBlockedRedirectHost::query()->count())->toBe(0)
        ->and(isClientFullyRevoked($hostClient))->toBeTrue();

    Event::assertDispatched(McpRedirectHostUnblocked::class, static fn (McpRedirectHostUnblocked $event): bool => $event->host === 'app.example'
        && $event->actorIdentifier === (string) $admin->getKey());
});

// --- Admin routes ----------------------------------------------------------------------------

/**
 * The product mounts the admin routes inside its own admin middleware; the
 * test's permission middleware lets only the user named `admin@` through.
 */
function registerAdminRoutes(): void
{
    Route::aliasMiddleware('test-admin', static function ($request, Closure $next) {
        abort_unless($request->user()?->getAttribute('is_admin') === true, 403);

        return $next($request);
    });

    Route::middleware(['web', 'auth'])->group(static fn () => McpOAuthAdminRoutes::register('test-admin'));
}

function adminUser(AuthorizeFlowTestCase $testCase): TestUser
{
    $admin = (new ReflectionMethod($testCase, 'createUser'))->invoke($testCase);
    $admin->setAttribute('is_admin', true);

    return $admin;
}

it('lists package clients and blocked hosts for an admin only', function (): void {
    registerAdminRoutes();
    ['client' => $client] = clientWithCredentials($this, 'https://app.example/callback');
    $this->createClient(['https://other.example/callback']);
    app(BlockRedirectHostAction::class)->execute('blocked.example', null, isSubdomainMatched: false, reason: 'Spam');

    $this->actingAs($this->createUser())->getJson('/mcp-oauth-clients')->assertForbidden();

    $response = $this->actingAs(adminUser($this))->getJson('/mcp-oauth-clients')->assertOk();

    expect($response->json('clients.data'))->toHaveCount(2)
        ->and(collect($response->json('clients.data'))->firstWhere('id', (string) $client->getKey()))->toMatchArray([
            'name' => 'Cursor',
            'redirectHosts' => ['app.example'],
            'isRevoked' => false,
            'hasEverAuthorized' => true,
        ])
        ->and($response->json('blockedHosts.0'))->toMatchArray([
            'host' => 'blocked.example',
            'matchMode' => 'exact',
            'reason' => 'Spam',
        ])
        ->and($response->json('blockedHosts.0.id'))->toBeString();
});

it('blocks, bulk blocks, blocks a host and unblocks it through the admin routes', function (): void {
    registerAdminRoutes();
    $admin = adminUser($this);
    ['client' => $client] = clientWithCredentials($this);
    ['client' => $bulkClient] = clientWithCredentials($this);

    $this->actingAs($admin)->postJson("/mcp-oauth-clients/{$client->getKey()}/block")->assertNoContent();
    $this->actingAs($admin)->postJson('/mcp-oauth-clients/bulk-block', ['client_ids' => [(string) $bulkClient->getKey()]])->assertNoContent();
    $this->actingAs($admin)->postJson('/mcp-oauth-clients/blocked-hosts', ['host' => 'Evil.example', 'match_mode' => 'exact'])->assertNoContent();

    $blockedHost = OAuthBlockedRedirectHost::query()->sole();

    expect(isClientFullyRevoked($client))->toBeTrue()
        ->and(isClientFullyRevoked($bulkClient))->toBeTrue()
        ->and($blockedHost->host)->toBe('evil.example')
        ->and($blockedHost->match_mode)->toBe('exact');

    $this->actingAs($admin)->deleteJson("/mcp-oauth-clients/blocked-hosts/{$blockedHost->public_id}")->assertNoContent();

    expect(OAuthBlockedRedirectHost::query()->count())->toBe(0);

    // A browser (or Inertia) form post goes back to the page.
    $this->actingAs($admin)->from('/admin/clients')->post("/mcp-oauth-clients/{$client->getKey()}/block")->assertRedirect('/admin/clients');
});

it('answers 404 for an unknown client and refuses invalid admin input with 422', function (array $request): void {
    registerAdminRoutes();
    [$method, $uri, $payload] = $request;

    $response = $this->actingAs(adminUser($this))->json($method, $uri, $payload);

    expect($response->getStatusCode())->toBe($uri === '/mcp-oauth-clients/'.UNKNOWN_CLIENT_ID.'/block' ? 404 : 422);
})->with([
    'unknown client' => [['POST', '/mcp-oauth-clients/'.UNKNOWN_CLIENT_ID.'/block', []]],
    'no client ids' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => []]]],
    'more than 100 ids (S40)' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => array_map(static fn (): string => (string) Str::uuid7(), range(1, 101))]]],
    'duplicate ids (S40)' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => [UNKNOWN_CLIENT_ID, UNKNOWN_CLIENT_ID]]]],
    'an id that is not a UUID' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => ['42']]]],
    'no host' => [['POST', '/mcp-oauth-clients/blocked-hosts', []]],
    'a host that does not normalise' => [['POST', '/mcp-oauth-clients/blocked-hosts', ['host' => 'bad_host.example']]],
    'an unknown match mode' => [['POST', '/mcp-oauth-clients/blocked-hosts', ['host' => 'app.example', 'match_mode' => 'suffix']]],
]);
