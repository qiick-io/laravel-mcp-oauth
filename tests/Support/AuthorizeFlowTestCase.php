<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use League\OAuth2\Server\AuthorizationServer;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Contracts\ApiKeyDoor;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\GrantAuthorizer;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Contracts\McpCredentialBinder;
use Qiick\McpOAuth\Data\ConsentOption;
use Qiick\McpOAuth\Data\ConsentOptions;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\RedirectUriGuard;
use Qiick\McpOAuth\Testing\FakeAdminSwitch;
use Qiick\McpOAuth\Testing\FakeApiKeyDoor;
use Qiick\McpOAuth\Testing\FakeConsentProvider;
use Qiick\McpOAuth\Testing\FakeGrantAuthorizer;
use Qiick\McpOAuth\Testing\FakeGrantStore;
use Qiick\McpOAuth\Testing\FakeMcpCredentialBinder;

/**
 * Boots Passport with its real tables, a signed-in-capable user model, a
 * login route and the package fakes, so the authorize → consent → approve /
 * deny flow runs end to end through the router (design §8.3).
 */
class AuthorizeFlowTestCase extends PassportBootedTestCase
{
    public const string REGISTERED_REDIRECT_URI = 'https://app.example/callback';

    /** RFC 7636 appendix B: the S256 challenge of CODE_VERIFIER. */
    public const string CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    public const string CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    public const string RESOURCE = 'https://mcp-oauth.test/mcp';

    /** @var array{private: string, public: string}|null */
    private static ?array $passportKeyPair = null;

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', TestUser::class);
        $app['config']->set('passport.guard', 'web');
    }

    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        $passportMigrations = glob(__DIR__.'/../../vendor/laravel/passport/database/migrations/2016_*.php') ?: [];

        foreach (['oauth_auth_codes', 'oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_clients'] as $passportTable) {
            Schema::dropIfExists($passportTable);
        }

        foreach ($passportMigrations as $passportMigration) {
            (require $passportMigration)->up();
        }

        // The product-owned binding columns, as the mcp-oauth-binding-stub-uuid stub adds them.
        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            $table->uuid('api_key_id')->nullable()->index();
            $table->string('audience', 512)->nullable();
        });
    }

    protected function setUp(): void
    {
        parent::setUp();

        Route::get('login', static fn (): string => 'login page')->name('login');
    }

    /**
     * Turns all three gates on with a usable key pair and binds the fakes.
     */
    protected function enableOAuth(?ConsentOptions $consentOptions = null): FakeConsentProvider
    {
        self::$passportKeyPair ??= self::generatePassportKeyPair();

        config()->set('passport.private_key', self::$passportKeyPair['private']);
        config()->set('passport.public_key', self::$passportKeyPair['public']);
        config()->set('mcp-oauth.enabled', true);
        config()->set('mcp-oauth.mcp_enabled', true);

        app()->instance(AdminSwitch::class, new FakeAdminSwitch(isEnabled: true));
        app()->forgetInstance(McpOAuthServer::class);
        app()->forgetInstance(RedirectUriGuard::class);
        // Its repositories depend on the gate (Passport's own while off).
        app()->forgetInstance(AuthorizationServer::class);

        $consentProvider = new FakeConsentProvider($consentOptions ?? self::defaultConsentOptions());
        app()->instance(ConsentProvider::class, $consentProvider);
        // The /mcp door's adapters (S81 requires them once OAuth is on).
        app()->instance(ApiKeyDoor::class, new FakeApiKeyDoor(['ak_valid']));
        app()->instance(McpCredentialBinder::class, new FakeMcpCredentialBinder);
        app()->instance(GrantAuthorizer::class, new FakeGrantAuthorizer);

        return $consentProvider;
    }

    public function grantStore(): FakeGrantStore
    {
        $grantStore = app(GrantStore::class);

        // A test may have wrapped it to hook into a request.
        if ($grantStore instanceof HookedGrantStore) {
            return $grantStore->grantStore;
        }

        assert($grantStore instanceof FakeGrantStore);

        return $grantStore;
    }

    public static function defaultConsentOptions(): ConsentOptions
    {
        return new ConsentOptions(
            scopes: [
                new ConsentOption('mcp:read', 'Read through MCP', grantable: true),
                new ConsentOption('mcp:write', 'Write through MCP', grantable: true),
                new ConsentOption('admin', 'Administer', grantable: false),
            ],
            roles: [
                new ConsentOption('editor', 'Editor', grantable: true),
                new ConsentOption('owner', 'Owner', grantable: false),
            ],
            resources: [
                new ConsentOption('news', 'News', grantable: true),
                new ConsentOption('events', 'Events', grantable: true),
                new ConsentOption('secret', 'Secret', grantable: false),
            ],
            resourcesRequired: true,
            canGrant: true,
        );
    }

    /**
     * @param  list<string>  $redirectUris
     */
    public function createClient(array $redirectUris = [self::REGISTERED_REDIRECT_URI], bool $isRevoked = false): Client
    {
        $client = (new Client)->forceFill([
            'id' => (string) Str::uuid7(),
            'name' => 'Cursor',
            'secret' => null,
            'redirect_uris' => $redirectUris,
            'grant_types' => ['authorization_code', 'refresh_token'],
            'revoked' => $isRevoked,
        ]);
        $client->save();
        // The row DCR writes for every client it registers: this is an MCP client.
        OAuthClientMetadata::query()->create([
            'client_id' => $client->getKey(),
            'registration_source' => 'dcr',
            'token_endpoint_auth_method' => 'none',
        ]);

        return $client;
    }

    protected function createUser(bool $isEmailVerified = true): TestUser
    {
        $user = new TestUser;
        $user->email_verified_at = $isEmailVerified ? now() : null;
        $user->save();

        return $user;
    }

    /**
     * @param  array<string, mixed>  $overrides  null removes the parameter
     * @return array<string, mixed>
     */
    protected function authorizeQuery(Client $client, array $overrides = []): array
    {
        $query = array_merge([
            'response_type' => 'code',
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => self::REGISTERED_REDIRECT_URI,
            'state' => 'state-1234',
            'scope' => 'mcp:use',
            'code_challenge' => self::CODE_CHALLENGE,
            'code_challenge_method' => 'S256',
            'resource' => self::RESOURCE,
        ], $overrides);

        return array_filter($query, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    protected function authorizeUrl(Client $client, array $overrides = []): string
    {
        return '/oauth/authorize?'.http_build_query($this->authorizeQuery($client, $overrides));
    }

    /**
     * @return array{private: string, public: string}
     */
    private static function generatePassportKeyPair(): array
    {
        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        assert($privateKey !== false);

        openssl_pkey_export($privateKey, $privatePem);
        $keyDetails = openssl_pkey_get_details($privateKey);

        assert(is_array($keyDetails) && is_string($privatePem));

        return [
            'private' => $privatePem,
            'public' => (string) $keyDetails['key'],
        ];
    }

    /**
     * Runs authorize → consent → approve (for a new user unless one is given)
     * and returns the code the client receives.
     *
     * @return array{code: string, user: TestUser}
     */
    public function obtainAuthorizationCode(Client $client, ?TestUser $user = null): array
    {
        $user ??= $this->createUser();

        $consentPage = $this->actingAs($user)
            ->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])
            ->assertOk();

        $approval = $this->post('/oauth/authorize', [
            'auth_token' => $consentPage->json('props.authToken'),
            'scopes' => ['mcp:read'],
            'role' => 'editor',
            'resources' => ['news'],
        ]);

        parse_str((string) parse_url((string) $approval->headers->get('Location'), PHP_URL_QUERY), $redirectParameters);

        // The token endpoint is stateless: forget the browser session.
        $this->app['auth']->forgetGuards();
        $this->flushSession();

        return ['code' => (string) $redirectParameters['code'], 'user' => $user];
    }

    /**
     * @param  array<string, mixed>  $overrides  null removes the parameter
     * @return array<string, mixed>
     */
    public function codeExchange(Client $client, string $code, array $overrides = []): array
    {
        return array_filter(array_merge([
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => self::REGISTERED_REDIRECT_URI,
            'code' => $code,
            'code_verifier' => self::CODE_VERIFIER,
            'resource' => self::RESOURCE,
        ], $overrides), static fn (mixed $value): bool => $value !== null);
    }
}
