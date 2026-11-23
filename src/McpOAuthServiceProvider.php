<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Carbon\CarbonInterval;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Inertia\Inertia;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use Laravel\Passport\Client;
use Laravel\Passport\Events\AccessTokenCreated;
use Laravel\Passport\Passport;
use Laravel\Passport\Scope;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Qiick\McpOAuth\Actions\BindAccessTokenAction;
use Qiick\McpOAuth\Bridge\FamilyRevokingRefreshTokenRepository;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\ConsentView;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Http\Controllers\AuthorizeClientController;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Internal\DisabledAdminSwitch;
use Qiick\McpOAuth\Services\ConsentPageService;
use Qiick\McpOAuth\Views\InertiaConsentView;
use ReflectionProperty;
use Symfony\Component\HttpFoundation\Response;

/**
 * Registers the package in a Laravel app. Auto-discovered through
 * `extra.laravel.providers` in composer.json.
 *
 * Always calls `Passport::ignoreRoutes()` and turns the device grant off in
 * `register()` (design Resolved #3 / #4). Token TTLs, the wire scope
 * (`tokensCan` / `defaultScopes`), stripping ClientCredentialsGrant,
 * `McpBearerTokenResponse`, rate limiters for DCR / authorize / token /
 * revoke (per-IP via ClientThrottleKey and per-client when known; 429 with
 * Retry-After), and the family-revoking refresh-token repository binding
 * land in `register()` / `boot()`, with the AccessTokenCreated binding. With
 * `mcp-oauth.enabled` on, boot fails closed when ConsentView, ConsentProvider
 * or GrantStore is not bound (S81); while it is false (the default), missing
 * product adapters are allowed so products can install before writing them.
 *
 * @api
 */
final class McpOAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/mcp-oauth.php', 'mcp-oauth');

        // Always: Passport must not register its own /oauth/* (S4).
        Passport::ignoreRoutes();
        Passport::$deviceCodeGrantEnabled = false;

        $this->app->singletonIf(AdminSwitch::class, DisabledAdminSwitch::class);

        // Design Resolved #9: the default consent page needs Inertia, which is only a suggest.
        if (class_exists(Inertia::class)) {
            $this->app->bindIf(ConsentView::class, InertiaConsentView::class);
        }

        // Passport gives its own AuthorizationController the session guard; the subclass needs it too.
        $this->app->when(AuthorizeClientController::class)
            ->needs(StatefulGuard::class)
            ->give(static function (Application $app): StatefulGuard {
                $guardName = $app->make(ConfigRepository::class)->get('passport.guard');
                $passportGuard = $app->make(AuthFactory::class)->guard(is_string($guardName) ? $guardName : null);

                assert($passportGuard instanceof StatefulGuard);

                return $passportGuard;
            });

        // Design §5.6: Passport resolves this concrete; products must bind GrantStore
        // before the AuthorizationServer is first resolved.
        $this->app->bind(PassportRefreshTokenRepository::class, function (Application $app): FamilyRevokingRefreshTokenRepository {
            return new FamilyRevokingRefreshTokenRepository(
                $app->make(Dispatcher::class),
                $app->make(GrantStore::class),
                $app->make(ConfigRepository::class),
            );
        });

        $this->app->singleton(BlockedHostCatalog::class, static fn (): BlockedHostCatalog => new BlockedHostCatalog);

        $this->app->singleton(RedirectUriGuard::class, function (Application $app): RedirectUriGuard {
            return new RedirectUriGuard($app->make(BlockedHostCatalog::class));
        });

        $this->app->singleton(ClientMetadataUriGuard::class, function (Application $app): ClientMetadataUriGuard {
            return new ClientMetadataUriGuard($app->make(RedirectUriGuard::class));
        });

        $this->app->singleton(McpOAuthServer::class, function (Application $app): McpOAuthServer {
            return new McpOAuthServer(
                $app->make(ConfigRepository::class),
                $app->make(AdminSwitch::class),
            );
        });

        $this->app->singleton(McpOAuthReadiness::class, function (Application $app): McpOAuthReadiness {
            return new McpOAuthReadiness($app->make(McpOAuthServer::class));
        });
    }

    public function boot(): void
    {
        // Core side tables load with the package (same pattern as laravel-oidc).
        // Opt out via mcp-oauth.migrations.load when the app owns the files.
        if ($this->app->make('config')->get('mcp-oauth.migrations.load', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        $this->configurePassportTokenLifetimes();
        $this->configurePassportScopes();
        Passport::useAuthorizationServerResponseType(new McpBearerTokenResponse);
        Passport::authorizationView(function (array $parameters): Response {
            // The shape AuthorizationController passes to withParameters().
            /** @var array{request: Request, user: Authenticatable, client: Client, scopes: list<Scope>, authToken: string} $parameters */
            return $this->app->make(ConsentPageService::class)->render($parameters);
        });
        $this->configureRateLimiters();
        $this->validateRemainingIntegerConfig();
        $this->bindAccessTokensOnCreation();
        $this->assertAdaptersBoundWhileEnabled();

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/mcp-oauth.php' => config_path('mcp-oauth.php'),
            ], 'mcp-oauth-config');

            $this->publishesMigrations([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'mcp-oauth-migrations');
        }
    }

    /**
     * Design §8.4: every token Passport mints is bound before the response
     * leaves. Synchronous on purpose; never queue this listener.
     */
    private function bindAccessTokensOnCreation(): void
    {
        $this->app->make(Dispatcher::class)->listen(AccessTokenCreated::class, function (AccessTokenCreated $event): void {
            $this->app->make(BindAccessTokenAction::class)->execute($event->tokenId, $event->userId, $event->clientId);
        });
    }

    /**
     * S81 / design §5.6: with `mcp-oauth.enabled` on, the OAuth endpoints
     * cannot work without these adapters, so boot fails with a clear message
     * instead of a 500 on the first request. Off, a product may install the
     * package before writing its adapters.
     *
     * @throws InvalidMcpOAuthConfigException
     */
    private function assertAdaptersBoundWhileEnabled(): void
    {
        if (! (bool) $this->app->make(ConfigRepository::class)->get('mcp-oauth.enabled')) {
            return;
        }

        $remediesByContract = [
            ConsentView::class => 'Install inertiajs/inertia-laravel for the default consent page, or bind your own ConsentView.',
            ConsentProvider::class => 'Bind the product ConsentProvider that says what a user may grant.',
            GrantStore::class => 'Bind the product GrantStore that stores consented grants.',
        ];

        foreach ($remediesByContract as $contract => $remedy) {
            if (! $this->app->bound($contract)) {
                throw InvalidMcpOAuthConfigException::missingAdapter($contract, $remedy);
            }
        }
    }

    /**
     * Applies access, refresh and auth-code TTLs from mcp-oauth config onto
     * Passport (global per app; products that already own Passport as an IdP
     * are out of scope for 1.x — design §3.3 Signaculum row). Invalid values
     * fail closed at boot (design §6); they are never floored or replaced.
     */
    private function configurePassportTokenLifetimes(): void
    {
        /** @var ConfigRepository $config */
        $config = $this->app->make(ConfigRepository::class);

        $accessTokenTtlMinutes = BoundedPositiveInt::require(
            $config->get('mcp-oauth.access_token_ttl_minutes'),
            'access_token_ttl_minutes',
            BoundedPositiveInt::ACCESS_TOKEN_TTL_MINUTES_MAX,
        );
        $refreshTokenTtlDays = BoundedPositiveInt::require(
            $config->get('mcp-oauth.refresh_token_ttl_days'),
            'refresh_token_ttl_days',
            BoundedPositiveInt::REFRESH_TOKEN_TTL_DAYS_MAX,
        );
        $authCodeTtlMinutes = BoundedPositiveInt::require(
            $config->get('mcp-oauth.auth_code_ttl_minutes'),
            'auth_code_ttl_minutes',
            BoundedPositiveInt::AUTH_CODE_TTL_MINUTES_MAX,
        );

        Passport::tokensExpireIn(CarbonInterval::minutes($accessTokenTtlMinutes));
        Passport::refreshTokensExpireIn(CarbonInterval::days($refreshTokenTtlDays));
        $this->hardenAuthorizationServer($authCodeTtlMinutes);
    }

    /**
     * Passport hardcodes AuthCodeGrant at PT10M and always enables
     * ClientCredentialsGrant. Patch the live AuthorizationServer: set the
     * validated auth-code TTL, and drop client_credentials so Passport’s
     * hard-coded `*` scope cannot be issued for MCP (design: auth code +
     * refresh only). Retrofits an already-resolved singleton.
     */
    private function hardenAuthorizationServer(int $authCodeTtlMinutes): void
    {
        $authCodeInterval = CarbonInterval::minutes($authCodeTtlMinutes);

        $harden = function (AuthorizationServer $authorizationServer) use ($authCodeInterval): void {
            $enabledGrantTypesProperty = new ReflectionProperty($authorizationServer, 'enabledGrantTypes');
            /** @var array<string, object> $enabledGrantTypes */
            $enabledGrantTypes = $enabledGrantTypesProperty->getValue($authorizationServer);

            foreach ($enabledGrantTypes as $grantIdentifier => $grant) {
                if ($grant instanceof ClientCredentialsGrant) {
                    unset($enabledGrantTypes[$grantIdentifier]);

                    continue;
                }

                if (! $grant instanceof AuthCodeGrant) {
                    continue;
                }

                $authCodeTtlProperty = new ReflectionProperty(AuthCodeGrant::class, 'authCodeTTL');
                $authCodeTtlProperty->setValue($grant, $authCodeInterval);
            }

            $enabledGrantTypesProperty->setValue($authorizationServer, $enabledGrantTypes);
        };

        $this->app->afterResolving(AuthorizationServer::class, $harden);

        if ($this->app->resolved(AuthorizationServer::class)) {
            $harden($this->app->make(AuthorizationServer::class));
        }
    }

    /**
     * Registers the wire scope descriptions and default scope (design §5.6).
     */
    private function configurePassportScopes(): void
    {
        /** @var McpOAuthServer $server */
        $server = $this->app->make(McpOAuthServer::class);

        Passport::tokensCan($server->scopeDescriptions());
        Passport::defaultScopes([McpOAuthServer::WIRE_SCOPE]);
    }

    /**
     * Named limiters for DCR, authorize, token and revoke (design §5.6).
     * Routes attach `throttle:mcp-oauth-*` when those endpoints land.
     * Per-IP keys use ClientThrottleKey (S29 / S30); per-client keys use
     * `client_id` or HTTP Basic username when present. Exceeded limits
     * answer 429 with Retry-After.
     */
    private function configureRateLimiters(): void
    {
        /** @var ConfigRepository $config */
        $config = $this->app->make(ConfigRepository::class);

        $registrationsPerMinute = $this->rateLimitPerMinute($config, 'registrations_per_minute');
        $authorizePerMinute = $this->rateLimitPerMinute($config, 'authorize_requests_per_minute');
        $authorizePerClient = $this->rateLimitPerMinute($config, 'authorize_requests_per_client_per_minute');
        $tokenPerMinute = $this->rateLimitPerMinute($config, 'token_requests_per_minute');
        $tokenPerClient = $this->rateLimitPerMinute($config, 'token_requests_per_client_per_minute');
        $revokePerMinute = $this->rateLimitPerMinute($config, 'revoke_requests_per_minute');
        $revokePerClient = $this->rateLimitPerMinute($config, 'revoke_requests_per_client_per_minute');

        RateLimiter::for('mcp-oauth-register', function (Request $request) use ($registrationsPerMinute): array {
            // DCR has no client_id yet — IP only.
            return $this->rateLimitsFor($request, 'register', $registrationsPerMinute, null);
        });

        RateLimiter::for('mcp-oauth-authorize', function (Request $request) use ($authorizePerMinute, $authorizePerClient): array {
            return $this->rateLimitsFor($request, 'authorize', $authorizePerMinute, $authorizePerClient);
        });

        RateLimiter::for('mcp-oauth-token', function (Request $request) use ($tokenPerMinute, $tokenPerClient): array {
            return $this->rateLimitsFor($request, 'token', $tokenPerMinute, $tokenPerClient);
        });

        RateLimiter::for('mcp-oauth-revoke', function (Request $request) use ($revokePerMinute, $revokePerClient): array {
            return $this->rateLimitsFor($request, 'revoke', $revokePerMinute, $revokePerClient);
        });
    }

    private function rateLimitPerMinute(ConfigRepository $config, string $configKey): int
    {
        return BoundedPositiveInt::require(
            $config->get('mcp-oauth.'.$configKey),
            $configKey,
            BoundedPositiveInt::RATE_LIMIT_PER_MINUTE_MAX,
        );
    }

    /**
     * Fail-closed check of the integer keys read later than boot (the
     * /mcp auth-failure limiter, the DCR cap, retention and CIMD). Their
     * features land or run on request or schedule; validating here keeps a
     * hostile or mistyped env from shipping until the first request finds it.
     */
    private function validateRemainingIntegerConfig(): void
    {
        /** @var ConfigRepository $config */
        $config = $this->app->make(ConfigRepository::class);

        $maximumsByConfigKey = [
            'mcp_auth_failures_per_minute' => BoundedPositiveInt::RATE_LIMIT_PER_MINUTE_MAX,
            'registrations_global_cap' => BoundedPositiveInt::REGISTRATIONS_GLOBAL_CAP_MAX,
            'unused_client_retention_hours' => BoundedPositiveInt::UNUSED_CLIENT_RETENTION_HOURS_MAX,
            'revoked_retention_days' => BoundedPositiveInt::REVOKED_RETENTION_DAYS_MAX,
            'cimd.max_document_bytes' => BoundedPositiveInt::CIMD_MAX_DOCUMENT_BYTES_MAX,
            'cimd.timeout_seconds' => BoundedPositiveInt::CIMD_TIMEOUT_SECONDS_MAX,
            'cimd.cache_min_seconds' => BoundedPositiveInt::CIMD_CACHE_SECONDS_MAX,
            'cimd.cache_max_seconds' => BoundedPositiveInt::CIMD_CACHE_SECONDS_MAX,
        ];

        $validatedValuesByConfigKey = [];

        foreach ($maximumsByConfigKey as $configKey => $maximum) {
            $validatedValuesByConfigKey[$configKey] = BoundedPositiveInt::require($config->get('mcp-oauth.'.$configKey), $configKey, $maximum);
        }

        $cacheMinSeconds = $validatedValuesByConfigKey['cimd.cache_min_seconds'];
        $cacheMaxSeconds = $validatedValuesByConfigKey['cimd.cache_max_seconds'];

        if ($cacheMinSeconds > $cacheMaxSeconds) {
            throw InvalidMcpOAuthConfigException::cimdCacheBoundsReversed($cacheMinSeconds, $cacheMaxSeconds);
        }
    }

    /**
     * @return list<Limit>
     */
    private function rateLimitsFor(Request $request, string $bucket, int $perIp, ?int $perClient): array
    {
        $tooManyRequests = static function (Request $rateLimitedRequest, array $headers) {
            return response()->json([
                'error' => 'temporarily_unavailable',
                'error_description' => 'Too many requests. Try again later.',
            ], 429, $headers);
        };

        $limits = [
            Limit::perMinute($perIp)
                ->by($bucket.':ip:'.ClientThrottleKey::fromRequest($request))
                ->response($tooManyRequests),
        ];

        if ($perClient === null) {
            return $limits;
        }

        $clientId = self::oauthClientIdFromRequest($request);

        if ($clientId === null) {
            return $limits;
        }

        $limits[] = Limit::perMinute($perClient)
            ->by($bucket.':client:'.$clientId)
            ->response($tooManyRequests);

        return $limits;
    }

    /**
     * Client id from the OAuth body/query or HTTP Basic username (Passport).
     */
    private static function oauthClientIdFromRequest(Request $request): ?string
    {
        $clientId = $request->input('client_id');

        if (is_string($clientId) && $clientId !== '') {
            return $clientId;
        }

        $basicUser = $request->getUser();

        if (is_string($basicUser) && $basicUser !== '') {
            return $basicUser;
        }

        return null;
    }
}
