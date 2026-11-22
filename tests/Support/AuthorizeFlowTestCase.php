<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\ConsentOption;
use Qiick\McpOAuth\Data\ConsentOptions;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\RedirectUriGuard;
use Qiick\McpOAuth\Testing\FakeAdminSwitch;
use Qiick\McpOAuth\Testing\FakeConsentProvider;
use Qiick\McpOAuth\Testing\FakeGrantStore;

/**
 * Boots Passport with its real tables, a signed-in-capable user model, a
 * login route and the package fakes, so the authorize → consent → approve /
 * deny flow runs end to end through the router (design §8.3).
 */
class AuthorizeFlowTestCase extends PassportBootedTestCase
{
    public const string REGISTERED_REDIRECT_URI = 'https://app.example/callback';

    public const string CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

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

        $consentProvider = new FakeConsentProvider($consentOptions ?? self::defaultConsentOptions());
        app()->instance(ConsentProvider::class, $consentProvider);

        return $consentProvider;
    }

    protected function grantStore(): FakeGrantStore
    {
        $grantStore = app(GrantStore::class);

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
    protected function createClient(array $redirectUris = [self::REGISTERED_REDIRECT_URI], bool $isRevoked = false): Client
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

        return $client;
    }

    protected function createUser(): TestUser
    {
        $user = new TestUser;
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
            'resource' => 'https://mcp-oauth.test/mcp',
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
}
