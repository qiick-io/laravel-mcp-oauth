<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\ClientThrottleKey;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Events\McpClientRegistered;
use Qiick\McpOAuth\Events\McpPassportKeysMissing;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
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
        ->assertJsonPath('redirect_uris.0', 'https://app.example/callback')
        // Metadata the client did not send is not answered as null.
        ->assertJsonMissingPath('logo_uri')
        ->assertJsonMissingPath('client_uri');

    expect(Client::query()->where('revoked', false)->count())->toBe(1);

    Event::assertDispatched(McpClientRegistered::class, function (McpClientRegistered $event): bool {
        return $event->displayHosts === ['app.example'];
    });
});

it('records every registered client as an MCP client in oauth_client_metadata', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
        'logo_uri' => 'https://app.example/logo.png',
        'client_uri' => 'https://app.example',
    ])->assertCreated()
        ->assertJsonPath('logo_uri', 'https://app.example/logo.png')
        ->assertJsonPath('client_uri', 'https://app.example');

    $metadata = OAuthClientMetadata::query()->where('client_id', $response->json('client_id'))->sole();

    expect($metadata->registration_source)->toBe('dcr')
        ->and($metadata->token_endpoint_auth_method)->toBe('none')
        ->and($metadata->client_id_issued_at)->not->toBeNull()
        ->and($metadata->logo_uri)->toBe('https://app.example/logo.png')
        ->and($metadata->client_uri)->toBe('https://app.example');
});

it('leaves no client behind when its metadata row cannot be written (S1)', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();
    Schema::drop('oauth_client_metadata');

    try {
        $this->postJson('/oauth/register', [
            'client_name' => 'Cursor',
            'redirect_uris' => ['https://app.example/callback'],
        ])->assertStatus(500)->assertJsonPath('error', 'server_error');

        expect(Client::query()->count())->toBe(0);
    } finally {
        (require __DIR__.'/../../database/migrations/2026_11_22_100000_create_oauth_client_metadata_table.php')->up();
    }
});

it('closes its transaction whatever laravel/mcp answers', function (array $body, int $status): void {
    Event::fake([McpClientRegistered::class]);
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();
    $passportConnection = Passport::client()->getConnection();
    $transactionLevelBefore = $passportConnection->transactionLevel();

    $this->postJson('/oauth/register', $body)->assertStatus($status);

    expect($passportConnection->transactionLevel())->toBe($transactionLevelBefore);
    // Only a registration that happened is announced.
    Event::assertDispatchedTimes(McpClientRegistered::class, $status === 201 ? 1 : 0);
})->with([
    'registered' => [['client_name' => 'Cursor', 'redirect_uris' => ['https://app.example/callback']], 201],
    'refused by laravel/mcp validation' => [['client_name' => 'Cursor'], 400],
]);

it('closes its transaction when laravel/mcp lets an exception out (U2)', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();
    // laravel/mcp resolves the ClientRepository outside its own try.
    app()->bind(ClientRepository::class, static fn () => throw new RuntimeException('client repository unavailable'));
    $passportConnection = Passport::client()->getConnection();
    $transactionLevelBefore = $passportConnection->transactionLevel();

    expect(fn () => $this->withoutExceptionHandling()->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
    ]))->toThrow(RuntimeException::class, 'client repository unavailable');

    expect($passportConnection->transactionLevel())->toBe($transactionLevelBefore);
});

it('accepts an upper-case HTTPS scheme for logo_uri', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
        'logo_uri' => 'HTTPS://app.example/logo.png',
    ])->assertCreated();
});

it('accepts only https for logo_uri and client_uri, which a consent page may show (N5)', function (string $field): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
        $field => 'http://app.example/page',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_client_metadata');

    expect(Client::query()->count())->toBe(0);
})->with(['logo_uri', 'client_uri']);

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
    // Persistent engines keep tables across runs.
    Schema::dropIfExists('product_oauth_clients');
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
        expect(SeparateTableClient::query()->count())->toBe(1);
    } finally {
        Passport::useClientModel(Client::class);
        Schema::dropIfExists('product_oauth_clients');
    }
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

// --- RFC 7591 response and client fields (M4, S7) ----------------------------

it('returns client_id_issued_at as epoch seconds (RFC 7591 §3.2.1)', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();
    $this->travelTo(now()->startOfSecond());

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
    ])->assertCreated()
        ->assertJsonPath('client_id_issued_at', now()->getTimestamp());

    expect(OAuthClientMetadata::query()->where('client_id', $response->json('client_id'))->sole()->client_id_issued_at?->getTimestamp())
        ->toBe(now()->getTimestamp());
});

it('stores and returns application_type, inferring it when the client sends none (S7)', function (?string $sent, array $redirectUris, string $expected): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $response = $this->postJson('/oauth/register', array_filter([
        'client_name' => 'Cursor',
        'redirect_uris' => $redirectUris,
        'application_type' => $sent,
    ], static fn (mixed $value): bool => $value !== null))->assertCreated()
        ->assertJsonPath('application_type', $expected);

    expect(OAuthClientMetadata::query()->where('client_id', $response->json('client_id'))->sole()->application_type)->toBe($expected);
})->with([
    'native, sent' => ['native', ['http://127.0.0.1:33418/callback'], 'native'],
    'web, sent' => ['web', ['https://app.example/callback'], 'web'],
    'web, sent with a loopback redirect' => ['web', ['http://127.0.0.1:33418/callback'], 'web'],
    'none, loopback only' => [null, ['http://localhost:8765/callback'], 'native'],
    'none, private-use scheme' => [null, ['cursor://anysphere.cursor-retrieval/oauth/callback'], 'native'],
    'none, https' => [null, ['https://app.example/callback'], 'web'],
    'none, https and loopback' => [null, ['https://app.example/callback', 'http://127.0.0.1/callback'], 'web'],
]);

it('stores and returns the other RFC 7591 client fields it accepts', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();
    $fields = [
        'tos_uri' => 'https://app.example/terms',
        'policy_uri' => 'https://app.example/privacy',
        'contacts' => ['security@app.example', 'ops@app.example'],
        'software_id' => '4NRB1-0XZABZI9E6-5SM3R',
        'software_version' => '2.1.0',
    ];

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
        ...$fields,
    ])->assertCreated();

    $metadata = OAuthClientMetadata::query()->where('client_id', $response->json('client_id'))->sole();

    foreach ($fields as $field => $value) {
        $response->assertJsonPath($field, $value);
        expect($metadata->{$field})->toBe($value);
    }
});

it('refuses client fields it cannot accept (RFC 7591 §3.2.2)', function (array $field): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
        ...$field,
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata')
        ->assertJsonPath('error_description', fn (mixed $description): bool => is_string($description) && $description !== '');

    expect(Client::query()->count())->toBe(0);
})->with([
    'an unknown application_type' => [['application_type' => 'desktop']],
    'application_type not a string' => [['application_type' => ['native']]],
    'tos_uri over http' => [['tos_uri' => 'http://app.example/terms']],
    'policy_uri on a private address' => [['policy_uri' => 'https://10.0.0.1/privacy']],
    'tos_uri over 2048 characters' => [['tos_uri' => 'https://app.example/'.str_repeat('t', 2029)]],
    'policy_uri over 2048 characters' => [['policy_uri' => 'https://app.example/'.str_repeat('p', 2029)]],
    'contacts a string' => [['contacts' => 'a@b.c']],
    'contacts an object' => [['contacts' => ['security' => 'a@b.c']]],
    'a contact that is not a string' => [['contacts' => [42]]],
    'an empty contact' => [['contacts' => ['']]],
    'more than ten contacts' => [['contacts' => array_map(static fn (int $contactNumber): string => "c{$contactNumber}@app.example", range(1, 11))]],
    'a contact over 320 characters' => [['contacts' => [str_repeat('a', 309).'@app.example']]],
    'software_id not a string' => [['software_id' => ['x']]],
    'software_id over 255 characters' => [['software_id' => str_repeat('i', 256)]],
    'software_version not a string' => [['software_version' => [2]]],
    'software_version over 255 characters' => [['software_version' => str_repeat('9', 256)]],
]);

it('returns no client field the client did not send, or sent as null', function (array $sentFields): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
        ...$sentFields,
    ])->assertCreated()
        ->assertJsonPath('application_type', 'web')
        ->assertJsonMissingPath('tos_uri')
        ->assertJsonMissingPath('policy_uri')
        ->assertJsonMissingPath('contacts')
        ->assertJsonMissingPath('software_id')
        ->assertJsonMissingPath('software_version');
})->with([
    'none sent' => [[]],
    'every one null' => [array_fill_keys(['application_type', 'tos_uri', 'policy_uri', 'contacts', 'software_id', 'software_version'], null)],
]);

it('refuses an empty contact even without ConvertEmptyStringsToNull', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $this->withoutMiddleware(ConvertEmptyStringsToNull::class)->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
        'contacts' => [''],
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_client_metadata');
});

it('treats an empty client field as not sent, even without ConvertEmptyStringsToNull (#32 review N2)', function (): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();

    $response = $this->withoutMiddleware(ConvertEmptyStringsToNull::class)->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://app.example/callback'],
        ...array_fill_keys(['logo_uri', 'client_uri', 'tos_uri', 'policy_uri', 'software_id', 'software_version'], ''),
    ])->assertCreated();

    $metadata = OAuthClientMetadata::query()->where('client_id', $response->json('client_id'))->sole();

    foreach (['logo_uri', 'client_uri', 'tos_uri', 'policy_uri', 'software_id', 'software_version'] as $field) {
        $response->assertJsonMissingPath($field);
        expect($metadata->{$field})->toBeNull();
    }
});

it('refuses the punycode of an IDN an admin blocked in Unicode, composed or not (S34)', function (string $blockedAs): void {
    enableMcpOAuthWithKeys();
    McpOAuthRoutes::register();
    $register = fn (): TestResponse => $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://xn--bcher-kva.example/callback'],
    ]);

    // Allowed until the block exists.
    $register()->assertCreated();

    // The row the admin block writes: the host normalised as admin input is.
    OAuthBlockedRedirectHost::query()->create(['host' => app(RedirectUriGuard::class)->normalizeHost($blockedAs), 'match_mode' => 'host_and_subdomains']);

    $this->postJson('/oauth/register', [
        'client_name' => 'Cursor',
        'redirect_uris' => ['https://xn--bcher-kva.example/callback'],
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_redirect_uri');
})->with([
    'composed (NFC)' => ["B\u{00FC}cher.example"],
    'decomposed (NFD)' => ["Bu\u{0308}cher.example"],
]);
