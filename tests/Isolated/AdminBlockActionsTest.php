<?php

declare(strict_types=1);

use Illuminate\Database\Events\TransactionBeginning;
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
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpClientBlockedEvent;
use Qiick\McpOAuth\Events\McpRedirectHostBlockedEvent;
use Qiick\McpOAuth\Events\McpRedirectHostUnblockedEvent;
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
 * A client with a live grant and, bound to it, an access token, its refresh
 * token and an auth code never exchanged: the rows consent and the token
 * endpoint write.
 *
 * @return array{client: Client, user: TestUser}
 */
function clientWithCredentials(AuthorizeFlowTestCase $testCase): array
{
    $client = $testCase->createClient();
    $user = (new ReflectionMethod($testCase, 'createUser'))->invoke($testCase);
    $grant = new GrantRecord((string) Str::uuid7(), (string) $client->getKey(), (string) $user->getKey(), false, ['mcp:read'], new DateTimeImmutable, null);
    $testCase->grantStore()->seed($grant);
    $accessTokenId = Str::random(80);
    $owner = ['user_id' => $user->getKey(), 'client_id' => $client->getKey(), 'scopes' => '["mcp:use"]', 'revoked' => false, 'expires_at' => now()->addHour()];

    DB::table('oauth_access_tokens')->insert([...$owner, 'id' => $accessTokenId, 'api_key_id' => $grant->id, 'audience' => AuthorizeFlowTestCase::RESOURCE, 'created_at' => now(), 'updated_at' => now()]);
    DB::table('oauth_refresh_tokens')->insert(['id' => Str::random(80), 'access_token_id' => $accessTokenId, 'revoked' => false, 'expires_at' => now()->addDays(30)]);
    DB::table('oauth_auth_codes')->insert([...$owner, 'id' => Str::random(80)]);

    return ['client' => $client, 'user' => $user];
}

function isClientRevoked(Client $client): bool
{
    return (bool) Passport::client()->newQuery()->whereKey($client->getKey())->value('revoked');
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
    Event::fake([McpClientBlockedEvent::class]);
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

    Event::assertDispatched(McpClientBlockedEvent::class, static fn (McpClientBlockedEvent $event): bool => $event->clientId === (string) $client->getKey()
        && $event->actorIdentifier === (string) $admin->getKey());
});

it('bulk blocks each listed client and ignores unknown or already revoked ones (S40)', function (): void {
    Event::fake([McpClientBlockedEvent::class]);
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

    Event::assertDispatchedTimes(McpClientBlockedEvent::class, 2);
});

it('blocks a host and its subdomains, normalised to ASCII, and blocks the clients that redirect there', function (): void {
    Event::fake([McpRedirectHostBlockedEvent::class, McpClientBlockedEvent::class]);
    $hostClient = $this->createClient(['https://xn--bcher-kva.example/callback']);
    $subdomainClient = $this->createClient(['https://app.xn--bcher-kva.example/callback']);
    $otherClient = $this->createClient(['https://other.example/callback']);
    $admin = $this->createUser();

    $blockedHost = app(BlockRedirectHostAction::class)->execute('Bücher.example', $admin, isSubdomainMatched: true, reason: 'Phishing');

    expect($blockedHost->host)->toBe('xn--bcher-kva.example')
        ->and($blockedHost->getAttribute('host_original'))->toBe('Bücher.example')
        ->and($blockedHost->match_mode)->toBe('host_and_subdomains')
        ->and($blockedHost->getAttribute('reason'))->toBe('Phishing')
        ->and($blockedHost->getAttribute('created_by'))->toBe($admin->getKey())
        ->and(isClientRevoked($hostClient))->toBeTrue()
        ->and(isClientRevoked($subdomainClient))->toBeTrue()
        ->and(isClientRevoked($otherClient))->toBeFalse();

    Event::assertDispatched(McpRedirectHostBlockedEvent::class, static fn (McpRedirectHostBlockedEvent $event): bool => $event->host === 'xn--bcher-kva.example'
        && $event->actorIdentifier === (string) $admin->getKey());
});

it('blocks only the host itself in exact mode, and once however often it is blocked', function (): void {
    $hostClient = $this->createClient(['https://app.example/callback']);
    $subdomainClient = $this->createClient(['https://login.app.example/callback']);

    app(BlockRedirectHostAction::class)->execute('app.example', null, isSubdomainMatched: false);
    app(BlockRedirectHostAction::class)->execute('app.example.', null, isSubdomainMatched: false);

    expect(OAuthBlockedRedirectHost::query()->where('host', 'app.example')->sole()->match_mode)->toBe('exact')
        ->and(isClientRevoked($hostClient))->toBeTrue()
        ->and(isClientRevoked($subdomainClient))->toBeFalse();
});

it('blocks every matching client across more than one chunk (S39)', function (): void {
    config()->set('mcp-oauth.host_block_chunk_size', 2);
    $matchingClients = array_map(fn (): Client => $this->createClient(['https://app.example/callback']), range(1, 5));
    $otherClient = $this->createClient(['https://other.example/callback']);

    app(BlockRedirectHostAction::class)->execute('app.example', null, isSubdomainMatched: true);

    foreach ($matchingClients as $matchingClient) {
        expect(isClientRevoked($matchingClient))->toBeTrue();
    }

    expect(isClientRevoked($otherClient))->toBeFalse();
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
    Event::fake([McpRedirectHostUnblockedEvent::class]);
    // The registered redirect URI is on app.example.
    ['client' => $hostClient] = clientWithCredentials($this);
    $blockedHost = app(BlockRedirectHostAction::class)->execute('app.example', null, isSubdomainMatched: true);
    $admin = $this->createUser();

    app(UnblockRedirectHostAction::class)->execute($blockedHost, $admin);

    expect(OAuthBlockedRedirectHost::query()->count())->toBe(0)
        ->and(isClientFullyRevoked($hostClient))->toBeTrue();

    Event::assertDispatched(McpRedirectHostUnblockedEvent::class, static fn (McpRedirectHostUnblockedEvent $event): bool => $event->host === 'app.example'
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
    ['client' => $client] = clientWithCredentials($this);
    // Two redirect URIs on one host and one on another: each host listed once.
    $this->createClient(['https://other.example/callback', 'https://other.example/second', 'https://third.example/callback']);
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
        ->and(collect($response->json('clients.data'))->firstWhere('name', 'Cursor')['createdAt'])->toMatch('/^\d{4}-\d{2}-\d{2}T/')
        ->and(collect($response->json('clients.data'))->pluck('redirectHosts')->all())->toContain(['other.example', 'third.example'])
        ->and($response->json('blockedHosts'))->toBeList()
        ->and($response->json('blockedHosts.0'))->toMatchArray([
            'host' => 'blocked.example',
            'matchMode' => 'exact',
            'reason' => 'Spam',
            'expiresAt' => null,
        ])
        ->and($response->json('blockedHosts.0.createdAt'))->toMatch('/^\d{4}-\d{2}-\d{2}T/')
        ->and($response->json('blockedHosts.0.id'))->toBeString();
});

it('lists clients 50 to a page', function (): void {
    registerAdminRoutes();
    array_map(fn (): Client => $this->createClient(), range(1, 51));

    $response = $this->actingAs(adminUser($this))->getJson('/mcp-oauth-clients?page=2')->assertOk();

    expect($response->json('clients.total'))->toBe(51)
        ->and($response->json('clients.per_page'))->toBe(50)
        ->and($response->json('clients.data'))->toHaveCount(1);
});

it('blocks, bulk blocks, blocks a host and unblocks it through the admin routes', function (): void {
    registerAdminRoutes();
    $admin = adminUser($this);
    ['client' => $client] = clientWithCredentials($this);
    ['client' => $bulkClient] = clientWithCredentials($this);

    $this->actingAs($admin)->postJson("/mcp-oauth-clients/{$client->getKey()}/block")->assertNoContent();
    $this->actingAs($admin)->postJson('/mcp-oauth-clients/bulk-block', ['client_ids' => [(string) $bulkClient->getKey()]])->assertNoContent();
    $this->actingAs($admin)->postJson('/mcp-oauth-clients/blocked-hosts', ['host' => 'Evil.example', 'match_mode' => 'exact', 'reason' => 'Phishing'])->assertNoContent();

    $blockedHost = OAuthBlockedRedirectHost::query()->sole();

    expect(isClientFullyRevoked($client))->toBeTrue()
        ->and(isClientFullyRevoked($bulkClient))->toBeTrue()
        ->and($blockedHost->host)->toBe('evil.example')
        ->and($blockedHost->match_mode)->toBe('exact')
        ->and($blockedHost->getAttribute('reason'))->toBe('Phishing');

    // A null match mode and reason are allowed: subdomains blocked, no reason.
    $this->actingAs($admin)->postJson('/mcp-oauth-clients/blocked-hosts', ['host' => 'spam.example', 'match_mode' => null, 'reason' => null])->assertNoContent();

    expect(OAuthBlockedRedirectHost::query()->where('host', 'spam.example')->sole()->match_mode)->toBe('host_and_subdomains');

    $this->actingAs($admin)->deleteJson("/mcp-oauth-clients/blocked-hosts/{$blockedHost->public_id}")->assertNoContent();

    expect(OAuthBlockedRedirectHost::query()->where('host', 'evil.example')->exists())->toBeFalse();

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
    'client ids missing' => [['POST', '/mcp-oauth-clients/bulk-block', []]],
    'client ids an object' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => ['first' => UNKNOWN_CLIENT_ID]]]],
    'a null client id' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => [null]]]],
    'more than 100 ids (S40)' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => array_map(static fn (): string => (string) Str::uuid7(), range(1, 101))]]],
    'duplicate ids (S40)' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => [UNKNOWN_CLIENT_ID, UNKNOWN_CLIENT_ID]]]],
    'an id that is not a UUID' => [['POST', '/mcp-oauth-clients/bulk-block', ['client_ids' => ['42']]]],
    'no host' => [['POST', '/mcp-oauth-clients/blocked-hosts', []]],
    'a host that is not a string' => [['POST', '/mcp-oauth-clients/blocked-hosts', ['host' => ['app.example']]]],
    'a host over 253 characters' => [['POST', '/mcp-oauth-clients/blocked-hosts', ['host' => str_repeat('a', 63).'.'.str_repeat('b', 63).'.'.str_repeat('c', 63).'.'.str_repeat('d', 62)]]],
    'a reason that is not a string' => [['POST', '/mcp-oauth-clients/blocked-hosts', ['host' => 'app.example', 'reason' => ['spam']]]],
    'a reason over 512 characters' => [['POST', '/mcp-oauth-clients/blocked-hosts', ['host' => 'app.example', 'reason' => str_repeat('r', 513)]]],
    'a host that does not normalise' => [['POST', '/mcp-oauth-clients/blocked-hosts', ['host' => 'bad_host.example']]],
    'an unknown match mode' => [['POST', '/mcp-oauth-clients/blocked-hosts', ['host' => 'app.example', 'match_mode' => 'suffix']]],
]);

it('never blocks a Passport client the package did not register', function (): void {
    registerAdminRoutes();
    $admin = adminUser($this);
    $productClient = (new Client)->forceFill([
        'id' => (string) Str::uuid7(),
        'name' => 'Product app',
        'secret' => null,
        'redirect_uris' => ['https://app.example/callback'],
        'grant_types' => ['authorization_code'],
        'revoked' => false,
    ]);
    $productClient->save();

    $this->actingAs($admin)->postJson("/mcp-oauth-clients/{$productClient->getKey()}/block")->assertNotFound();
    $this->actingAs($admin)->postJson('/mcp-oauth-clients/bulk-block', ['client_ids' => [(string) $productClient->getKey()]])->assertNoContent();

    expect(isClientRevoked($productClient))->toBeFalse()
        ->and($this->actingAs($admin)->getJson('/mcp-oauth-clients')->json('clients.data'))->toBe([]);
});

it('shows a client as ever authorised once approved, after its grant is purged (#39 review m1)', function (): void {
    registerAdminRoutes();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update(['first_authorized_at' => now()->subDays(100)]);

    $listedClient = collect($this->actingAs(adminUser($this))->getJson('/mcp-oauth-clients')->assertOk()->json('clients.data'))
        ->firstWhere('id', (string) $client->getKey());

    expect($listedClient['hasEverAuthorized'])->toBeTrue();
});

it('needs a signed-in user before any permission (#39 review m2)', function (): void {
    registerAdminRoutes();

    $this->getJson('/mcp-oauth-clients')->assertUnauthorized();
    $this->postJson('/mcp-oauth-clients/blocked-hosts', ['host' => 'evil.example'])->assertUnauthorized();
});

it('blocks a host without one transaction around the client walk (S39)', function (): void {
    config()->set('mcp-oauth.host_block_chunk_size', 2);
    array_map(fn (): Client => $this->createClient(['https://app.example/callback']), range(1, 3));
    $this->createClient(['https://other.example/callback']);
    $baseLevel = DB::transactionLevel();
    $openedLevels = [];
    Event::listen(TransactionBeginning::class, static function (TransactionBeginning $event) use (&$openedLevels, $baseLevel): void {
        $openedLevels[] = $event->connection->transactionLevel() - $baseLevel;
    });

    app(BlockRedirectHostAction::class)->execute('app.example', null, isSubdomainMatched: true);

    // One short transaction for the block row and its audit entry (firstOrCreate
    // may add a savepoint inside it), then one per blocked client, never nested.
    expect(array_slice($openedLevels, -3))->toBe([1, 1, 1])
        ->and(array_filter($openedLevels, static fn (int $level): bool => $level === 1))->toHaveCount(4);
});
