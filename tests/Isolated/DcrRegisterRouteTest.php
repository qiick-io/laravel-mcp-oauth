<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\ClientThrottleKey;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Events\McpClientRegistered;
use Qiick\McpOAuth\Events\McpPassportKeysMissing;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\RedirectUriGuard;
use Qiick\McpOAuth\Testing\FakeAdminSwitch;
use Qiick\McpOAuth\Tests\Support\PassportBootedTestCase;
use Qiick\McpOAuth\Tests\Support\SeparateTableClient;

uses(PassportBootedTestCase::class);

/**
 * @return array{private: string, public: string}
 */
function generatePassportKeyPair(): array
{
    $privateKey = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    expect($privateKey)->not->toBeFalse();

    openssl_pkey_export($privateKey, $privatePem);
    $details = openssl_pkey_get_details($privateKey);

    expect($details)->toBeArray()
        ->and($details['key'] ?? null)->toBeString();

    return [
        'private' => $privatePem,
        'public' => $details['key'],
    ];
}

function enableMcpOAuthWithKeys(): void
{
    $keys = generatePassportKeyPair();

    config()->set('passport.private_key', $keys['private']);
    config()->set('passport.public_key', $keys['public']);
    config()->set('mcp-oauth.enabled', true);
    config()->set('mcp-oauth.mcp_enabled', true);
    config()->set('mcp.redirect_domains', ['*']);
    config()->set('mcp.custom_schemes', ['cursor']);

    app()->instance(AdminSwitch::class, new FakeAdminSwitch(isEnabled: true));
    app()->forgetInstance(McpOAuthServer::class);
    app()->forgetInstance(RedirectUriGuard::class);
}

function ensureOauthClientsTable(): void
{
    Schema::dropIfExists('oauth_clients');

    Schema::create('oauth_clients', function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->nullableMorphs('owner');
        $table->string('name');
        $table->string('secret')->nullable();
        $table->string('provider')->nullable();
        $table->text('redirect_uris');
        $table->text('grant_types');
        $table->text('scopes')->nullable();
        $table->boolean('revoked');
        $table->timestamps();
    });
}

beforeEach(function (): void {
    ensureOauthClientsTable();
    RateLimiter::clear('mcp-oauth-register');
});

it('with OAuth off matches an unregistered /oauth/register byte-for-byte on every method', function (string $method): void {
    config()->set('app.debug', false);
    config()->set('mcp-oauth.enabled', false);

    $server = ['HTTP_ACCEPT' => 'application/json'];

    // Baseline: the path was never registered (true router 404).
    $unregisteredResponse = $this->call($method, '/oauth/register', server: $server);

    McpOAuthRoutes::register();

    // Gated registration must be indistinguishable from that baseline.
    $gatedResponse = $this->call($method, '/oauth/register', server: $server);

    expect($gatedResponse->getStatusCode())->toBe($unregisteredResponse->getStatusCode())
        ->and($gatedResponse->headers->get('Allow'))->toBe($unregisteredResponse->headers->get('Allow'));

    // HEAD must not carry a body; Laravel's missing-route HEAD still echoes JSON
    // in some versions, so compare the body only for methods that keep one.
    if ($method !== 'HEAD') {
        expect($gatedResponse->getContent())->toBe($unregisteredResponse->getContent())
            ->and($gatedResponse->headers->get('Content-Type'))->toBe($unregisteredResponse->headers->get('Content-Type'));
    }
})->with(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

it('answers 503 temporarily_unavailable when Passport keys are missing', function (): void {
    Event::fake([McpPassportKeysMissing::class]);

    config()->set('mcp-oauth.enabled', true);
    config()->set('mcp-oauth.mcp_enabled', true);
    config()->set('passport.private_key', null);
    config()->set('passport.public_key', null);
    // Empty env keys must not fall through to readable files.
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    app()->instance(AdminSwitch::class, new FakeAdminSwitch(isEnabled: true));
    app()->forgetInstance(McpOAuthServer::class);

    $missingKeyDirectory = sys_get_temp_dir().'/mcp-oauth-missing-keys-'.uniqid('', true);
    mkdir($missingKeyDirectory, 0700);
    Passport::loadKeysFrom($missingKeyDirectory);

    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'No Keys',
        'redirect_uris' => ['https://app.example/callback'],
    ])->assertStatus(503)
        ->assertJsonPath('error', 'temporarily_unavailable')
        ->assertJsonPath(
            'error_description',
            'OAuth is unavailable because Passport keys are missing.',
        );

    Event::assertDispatched(McpPassportKeysMissing::class);
});

it('registers a public client through the redirect URI guard', function (): void {
    Event::fake([McpClientRegistered::class]);
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
    ]);

    $response->assertCreated()
        ->assertJsonPath('token_endpoint_auth_method', 'none')
        ->assertJsonPath('redirect_uris.0', 'https://app.example/callback');

    expect(Client::query()->where('revoked', false)->count())->toBe(1);

    Event::assertDispatched(McpClientRegistered::class, function (McpClientRegistered $event): bool {
        return $event->displayHosts === ['app.example'];
    });
});

it('refuses a fragment redirect_uri via the guard before Passport create (B3)', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Fragment',
        'redirect_uris' => ['https://app.example/callback#frag'],
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');

    expect(Client::query()->count())->toBe(0);
});

it('refuses registration for a blocked redirect host', function (): void {
    enableMcpOAuthWithKeys();
    OAuthBlockedRedirectHost::query()->create([
        'host' => 'evil.test',
        'match_mode' => 'host_and_subdomains',
    ]);
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Blocked',
        'redirect_uris' => ['https://evil.test/callback'],
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');

    expect(Client::query()->count())->toBe(0);
});

it('answers 503 when the global client cap is reached', function (): void {
    enableMcpOAuthWithKeys();
    config()->set('mcp-oauth.registrations_global_cap', 1);

    (new Client)->forceFill([
        'id' => (string) Str::uuid7(),
        'name' => 'Existing',
        'secret' => null,
        'redirect_uris' => ['https://existing.example/cb'],
        'grant_types' => ['authorization_code', 'refresh_token'],
        'revoked' => false,
    ])->save();

    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Over Cap',
        'redirect_uris' => ['https://app.example/callback'],
    ])->assertStatus(503)
        ->assertJsonPath('error', 'temporarily_unavailable');
});

it('counts the cap on the client model Passport writes to', function (): void {
    enableMcpOAuthWithKeys();
    config()->set('mcp-oauth.registrations_global_cap', 1);
    Schema::create('product_oauth_clients', function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->nullableMorphs('owner');
        $table->string('name');
        $table->string('secret')->nullable();
        $table->string('provider')->nullable();
        $table->text('redirect_uris');
        $table->text('grant_types');
        $table->boolean('revoked');
        $table->timestamps();
    });
    Passport::useClientModel(SeparateTableClient::class);

    try {
        (new SeparateTableClient)->forceFill([
            'id' => (string) Str::uuid7(),
            'name' => 'Existing',
            'redirect_uris' => ['https://existing.example/cb'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'revoked' => false,
        ])->save();

        McpOAuthRoutes::register();

        $this->postJson('/oauth/register', [
            'client_name' => 'Over Cap',
            'redirect_uris' => ['https://app.example/callback'],
        ])->assertStatus(503)
            ->assertJsonPath('error', 'temporarily_unavailable');
    } finally {
        Passport::useClientModel(Client::class);
    }

    expect(SeparateTableClient::query()->count())->toBe(1);
});

it('refuses a subdomain of a blocked host only when the row matches subdomains', function (): void {
    enableMcpOAuthWithKeys();
    OAuthBlockedRedirectHost::query()->create(['host' => 'exact.test', 'match_mode' => 'exact']);
    OAuthBlockedRedirectHost::query()->create(['host' => 'wide.test', 'match_mode' => 'host_and_subdomains']);
    // An unknown mode is read as the wider block, never as a narrower one.
    OAuthBlockedRedirectHost::query()->create(['host' => 'typo.test', 'match_mode' => 'Exact']);
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Subdomain of an exact block',
        'redirect_uris' => ['https://app.exact.test/callback'],
    ])->assertStatus(201);

    foreach (['https://exact.test/callback', 'https://wide.test/callback', 'https://app.wide.test/callback', 'https://app.typo.test/callback'] as $blockedRedirectUri) {
        $this->postJson('/oauth/register', [
            'client_name' => 'Blocked',
            'redirect_uris' => [$blockedRedirectUri],
        ])->assertStatus(400)
            ->assertJsonPath('error', 'invalid_redirect_uri');
    }
});

it('limits unauthenticated registrations per address with Retry-After', function (): void {
    enableMcpOAuthWithKeys();

    RateLimiter::for('mcp-oauth-register', function (Request $request): array {
        return [
            Limit::perMinute(2)
                ->by('register:ip:'.ClientThrottleKey::fromRequest($request))
                ->response(function (mixed $request, array $headers) {
                    return response()->json([
                        'message' => 'Too Many Attempts.',
                    ], 429, $headers);
                }),
        ];
    });

    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Throttle',
        'redirect_uris' => ['https://app.example/callback'],
    ])->assertCreated();

    $this->postJson('/oauth/register', [
        'client_name' => 'Throttle 2',
        'redirect_uris' => ['https://app.example/callback-2'],
    ])->assertCreated();

    $this->postJson('/oauth/register', [
        'client_name' => 'Throttle 3',
        'redirect_uris' => ['https://app.example/callback-3'],
    ])->assertStatus(429)
        ->assertHeader('Retry-After');
});

it('throws when a foreign passport route already exists', function (): void {
    Route::post('oauth/token', fn () => 'x')->name('passport.token');

    expect(fn () => McpOAuthRoutes::register())
        ->toThrow(LogicException::class, 'passport.token');
});

it('allows register beside a non-passport named route', function (): void {
    Route::get('health', fn () => 'ok')->name('health.check');

    expect(fn () => McpOAuthRoutes::register())->not->toThrow(LogicException::class);
    expect(Route::has('mcp.oauth.register'))->toBeTrue();
});

it('answers 405 with Allow POST for non-POST methods when OAuth is on', function (string $method): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->call($method, '/oauth/register', server: ['HTTP_ACCEPT' => 'application/json'])
        ->assertStatus(405)
        ->assertHeader('Allow', 'POST');
})->with(['GET', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

it('still detects a passport route registered after a non-passport name', function (): void {
    Route::get('first', fn () => 'ok')->name('app.first');
    Route::get('second', fn () => 'ok')->name('passport.authorizations.approve');

    expect(fn () => McpOAuthRoutes::register())
        ->toThrow(LogicException::class, 'passport.authorizations.approve');
});

it('refuses redirect_uris sent as a JSON object', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Object Uris',
        'redirect_uris' => ['x' => 'https://app.example/callback'],
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');

    expect(Client::query()->count())->toBe(0);
});

it('refuses client_name with bidi or control characters', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => "Good\u{202E}lacitirC",
        'redirect_uris' => ['https://app.example/callback'],
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');

    expect(Client::query()->count())->toBe(0);
});

it('refuses logo_uri that fails the metadata URI guard', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Logo',
        'redirect_uris' => ['https://app.example/callback'],
        'logo_uri' => 'javascript:alert(1)',
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');

    expect(Client::query()->count())->toBe(0);
});

it('refuses logo_uri pointing at a private or loopback IP', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Private Logo',
        'redirect_uris' => ['https://app.example/callback'],
        'logo_uri' => 'https://169.254.169.254/latest',
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');

    expect(Client::query()->count())->toBe(0);
});

it('accepts client_name with emoji ZWJ and Persian ZWNJ', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => "Team \u{1F468}\u{200D}\u{1F469} می\u{200C}خواهم",
        'redirect_uris' => ['https://app.example/callback'],
    ])->assertCreated();
});

it('refuses an oversized registration body with 413', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $oversizedPayload = json_encode([
        'client_name' => 'Huge',
        'redirect_uris' => ['https://app.example/callback'],
        'padding' => str_repeat('a', 70_000),
    ], JSON_THROW_ON_ERROR);

    $this->call(
        'POST',
        '/oauth/register',
        content: $oversizedPayload,
        server: [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'CONTENT_LENGTH' => (string) strlen($oversizedPayload),
        ],
    )->assertStatus(413)
        ->assertJsonPath('error', 'invalid_request');

    expect(Client::query()->count())->toBe(0);
});
