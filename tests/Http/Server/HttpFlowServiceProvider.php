<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Http\Server;

use Illuminate\Http\Client\Factory;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Mcp\Facades\Mcp;
use Laravel\Mcp\Server\Middleware\AddWwwAuthenticateHeader;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Contracts\ApiKeyDoor;
use Qiick\McpOAuth\Contracts\ClientMetadataDocumentFetcherContract;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\ConsentView;
use Qiick\McpOAuth\Contracts\GrantAuthorizer;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Contracts\McpCredentialBinder;
use Qiick\McpOAuth\Http\Middleware\McpBearerDoorMiddleware;
use Qiick\McpOAuth\Http\Middleware\McpChallengeMiddleware;
use Qiick\McpOAuth\Internal\OutboundClientMetadataDocumentFetcher;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Testing\FakeAdminSwitch;
use Qiick\McpOAuth\Testing\FakeApiKeyDoor;
use Qiick\McpOAuth\Testing\FakeConsentProvider;
use Qiick\McpOAuth\Testing\FakeGrantAuthorizer;
use Qiick\McpOAuth\Testing\FakeMcpCredentialBinder;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\TestDatabaseConnection;
use Qiick\McpOAuth\Tests\Support\TestUser;
use Qiick\Outbound\Http\OutboundHttpStackData;
use Qiick\Outbound\Testing\FakeHostResolver;
use Qiick\Outbound\Testing\FakeOutboundHttpFactory;

/**
 * The product side of the `http` group: what an adopting app wires (design
 * §5), with state every `php -S` worker shares. Configured from the process
 * environment the test passes:
 *
 * - `MCP_HTTP_APP_URL`: the server's own origin, so issuer and resource match
 *   the address the client calls;
 * - `MCP_HTTP_STORAGE`: a directory for the Passport keys, the cache files
 *   and, on SQLite, the database file.
 *
 * Each request also reads three flag files in that directory, so a test can
 * switch the running servers into the states of design §11.1 steps 6 and 7
 * (and must remove the file afterwards).
 */
final class HttpFlowServiceProvider extends ServiceProvider
{
    /** The product's admin switch is off. */
    public const string ADMIN_SWITCH_OFF_FLAG = 'admin-switch-off';

    /** `mcp-oauth.enabled` is false. */
    public const string CONFIG_OFF_FLAG = 'config-off';

    /** Passport finds no key files. */
    public const string KEYS_MISSING_FLAG = 'keys-missing';

    public const string CIMD_ENABLED_FLAG = 'cimd-enabled';

    public const string CIMD_CLIENT_IDENTIFIER = 'https://client.example/oauth-client.json';

    public function register(): void
    {
        $storagePath = (string) getenv('MCP_HTTP_STORAGE');
        $config = $this->app['config'];

        // Fixed, not random: every worker must read the others' cookies.
        $config->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $config->set('app.url', (string) getenv('MCP_HTTP_APP_URL'));
        $config->set('app.timezone', 'UTC');
        TestDatabaseConnection::configure($config, $storagePath.'/database.sqlite');
        // Errors reach the test through the server's stderr.
        $config->set('logging.default', 'stderr');
        $config->set('session.driver', 'cookie');
        $config->set('cache.default', 'file');
        $config->set('cache.stores.file', ['driver' => 'file', 'path' => $storagePath.'/cache', 'lock_path' => $storagePath.'/cache']);
        $config->set('auth.providers.users.model', TestUser::class);
        $config->set('passport.guard', 'web');
        $config->set('mcp.redirect_domains', ['*']);
        $config->set('mcp-oauth.enabled', ! is_file($storagePath.'/'.self::CONFIG_OFF_FLAG));
        $config->set('mcp-oauth.mcp_enabled', true);

        if (is_file($storagePath.'/'.self::CIMD_ENABLED_FLAG)) {
            $factory = FakeOutboundHttpFactory::fake([
                self::CIMD_CLIENT_IDENTIFIER => Factory::response([
                    'client_id' => self::CIMD_CLIENT_IDENTIFIER,
                    'client_name' => 'CIMD HTTP client',
                    'redirect_uris' => ['http://127.0.0.1:9/callback'],
                    'grant_types' => ['authorization_code', 'refresh_token'],
                ]),
            ]);
            $factory->preventStrayRequests();
            $resolver = (new FakeHostResolver)->with('client.example', ['8.8.8.8']);
            $this->app->instance(ClientMetadataDocumentFetcherContract::class, new OutboundClientMetadataDocumentFetcher(
                $config,
                OutboundHttpStackData::make($resolver, httpFactory: $factory),
            ));
        }

        $this->app->instance(AdminSwitch::class, new FakeAdminSwitch(isEnabled: ! is_file($storagePath.'/'.self::ADMIN_SWITCH_OFF_FLAG)));
        $this->app->instance(ConsentProvider::class, new FakeConsentProvider(AuthorizeFlowTestCase::defaultConsentOptions()));
        $this->app->bind(ConsentView::class, HtmlConsentView::class);
        $this->app->bind(GrantStore::class, DatabaseGrantStore::class);
        $this->app->instance(GrantAuthorizer::class, new FakeGrantAuthorizer);
        $this->app->instance(ApiKeyDoor::class, new FakeApiKeyDoor(['ak_valid']));
        $this->app->instance(McpCredentialBinder::class, new FakeMcpCredentialBinder);

        // A directory without keys stands for keys deleted or never generated.
        Passport::loadKeysFrom(is_file($storagePath.'/'.self::KEYS_MISSING_FLAG) ? $storagePath.'/cache' : $storagePath);
    }

    public function boot(): void
    {
        // The package has merged its shipped CIMD settings by this point.
        $storagePath = (string) getenv('MCP_HTTP_STORAGE');
        $this->app['config']->set('mcp-oauth.cimd.enabled', is_file($storagePath.'/'.self::CIMD_ENABLED_FLAG));

        McpOAuthRoutes::register();

        Route::middleware('web')->group(static function (): void {
            // The CSRF token a login form would carry.
            Route::get('login', static fn (): string => '<input name="_token" value="'.e(csrf_token()).'">')->name('login');

            // Signs in the user the test created: authentication is the
            // product's, the package only needs a signed-in user.
            Route::post('login', static function (Request $request): RedirectResponse {
                Auth::loginUsingId($request->integer('user_id'));

                return redirect()->intended('/');
            });
        });

        Mcp::web('mcp', HttpFlowMcpServer::class)
            ->withoutMiddleware(AddWwwAuthenticateHeader::class)
            ->middleware([McpChallengeMiddleware::class, McpBearerDoorMiddleware::class]);
    }
}
