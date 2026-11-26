<?php

declare(strict_types=1);

use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Actions\SwitchMcpOAuthAction;
use Qiick\McpOAuth\Events\McpOAuthDisabled;
use Qiick\McpOAuth\Events\McpOAuthEnabled;
use Qiick\McpOAuth\Exceptions\McpOAuthCannotBeEnabledException;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * The admin switch rules (design §4.3): switching on is refused, with a
 * reason, while OAuth could not serve; switching on or off writes the
 * product's store and emits an event. Switching off is always allowed.
 */

/**
 * The product's AdminSwitch store, as the action's persist callback sees it.
 *
 * @return object{writes: list<bool>, persist: Closure(bool): void}
 */
function switchStore(): object
{
    $store = new class
    {
        /** @var list<bool> */
        public array $writes = [];
    };
    $store->persist = static function (bool $isEnabled) use ($store): void {
        $store->writes[] = $isEnabled;
    };

    return $store;
}

beforeEach(function (): void {
    Event::fake([McpOAuthEnabled::class, McpOAuthDisabled::class]);
    $this->enableOAuth();
    McpOAuthRoutes::register();
});

it('refuses to switch on unless the package itself serves its routes at the origin (Codex review of #62)', function (Closure $mountRoutes, string $problem): void {
    Route::setRoutes(new RouteCollection);
    $mountRoutes();
    Route::getRoutes()->refreshNameLookups();
    $store = switchStore();

    expect(fn () => app(SwitchMcpOAuthAction::class)->execute(true, null, $store->persist))
        ->toThrow(static fn (McpOAuthCannotBeEnabledException $exception) => expect($exception->getMessage())->toContain($problem));

    expect($store->writes)->toBe([]);
})->with([
    'not mounted' => [static fn () => null, 'passport.token is not mounted'],
    'mounted under a prefix' => [static fn () => Route::prefix('api')->group(static fn () => McpOAuthRoutes::register()), 'passport.token is not the package\'s POST /oauth/token'],
    'a foreign handler under the token name' => [static function (): void {
        McpOAuthRoutes::register();
        Route::post('oauth/token', static fn (): string => 'foreign')->name('passport.token');
    }, 'passport.token is not the package\'s POST /oauth/token'],
    'beside laravel/mcp\'s own OAuth routes' => [static function (): void {
        McpOAuthRoutes::register();
        Route::get('.well-known/oauth-protected-resource/{path}', static fn (): string => '')->where('path', '.*')->name('mcp.oauth.protected-resource.nested');
    }, 'laravel/mcp OAuth route mcp.oauth.protected-resource.nested'],
]);

it('switches on when OAuth can serve, writing the store and telling the product', function (): void {
    $store = switchStore();
    $admin = $this->createUser();

    app(SwitchMcpOAuthAction::class)->execute(true, $admin, $store->persist);

    expect($store->writes)->toBe([true]);
    Event::assertDispatched(McpOAuthEnabled::class, static fn (McpOAuthEnabled $event): bool => $event->actorIdentifier === (string) $admin->getKey());
    Event::assertNotDispatched(McpOAuthDisabled::class);
});

it('switches off whatever the state, with or without an actor', function (): void {
    $store = switchStore();
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    Passport::loadKeysFrom(sys_get_temp_dir().'/mcp-oauth-no-keys-'.uniqid());

    app(SwitchMcpOAuthAction::class)->execute(false, null, $store->persist);

    expect($store->writes)->toBe([false]);
    Event::assertDispatched(McpOAuthDisabled::class, static fn (McpOAuthDisabled $event): bool => $event->actorIdentifier === null);
    Event::assertNotDispatched(McpOAuthEnabled::class);
});

it('refuses to switch on, with the reason, while OAuth could not serve', function (string $state, string $reason): void {
    match ($state) {
        'keys missing' => (static function (): void {
            config()->set('passport.private_key', '');
            config()->set('passport.public_key', '');
            Passport::loadKeysFrom(sys_get_temp_dir().'/mcp-oauth-no-keys-'.uniqid());
        })(),
        'APP_URL not absolute' => config()->set('app.url', 'localhost'),
        'keys that are not keys' => config()->set(['passport.private_key' => 'not a private key', 'passport.public_key' => 'not a public key']),
        'keys from two different pairs' => config()->set('passport.public_key', (string) openssl_pkey_get_details(openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]))['key']),
        'a foreign Passport route' => Route::get('oauth/device', static fn (): string => 'device')->name('passport.device'),
    };
    Route::getRoutes()->refreshNameLookups();
    $store = switchStore();

    expect(fn () => app(SwitchMcpOAuthAction::class)->execute(true, null, $store->persist))
        ->toThrow(static fn (McpOAuthCannotBeEnabledException $exception) => expect($exception->getMessage())->toBe($reason));

    expect($store->writes)->toBe([]);
    Event::assertNotDispatched(McpOAuthEnabled::class);
})->with([
    'keys missing' => ['keys missing', 'OAuth cannot be switched on while the Passport keys are missing: run passport:keys.'],
    'APP_URL not absolute' => ['APP_URL not absolute', 'OAuth cannot be switched on until APP_URL is an absolute http(s) URL.'],
    'keys that are not keys' => ['keys that are not keys', 'OAuth cannot be switched on: the Passport keys are not a usable matching pair.'],
    'keys from two different pairs' => ['keys from two different pairs', 'OAuth cannot be switched on: the Passport keys are not a usable matching pair.'],
    'a foreign Passport route' => ['a foreign Passport route', 'OAuth cannot be switched on until McpOAuthRoutes::register() alone serves the OAuth routes at the origin: foreign Passport route passport.device.'],
]);

it('refuses to switch on while APP_URL is not a usable issuer', function (string $appUrl): void {
    config()->set('app.url', $appUrl);
    $store = switchStore();

    expect(fn () => app(SwitchMcpOAuthAction::class)->execute(true, null, $store->persist))
        ->toThrow(static fn (McpOAuthCannotBeEnabledException $exception) => expect($exception->getMessage())->toBe('OAuth cannot be switched on until APP_URL is an absolute http(s) URL.'));

    expect($store->writes)->toBe([]);
})->with([
    'no authority, a query' => ['http://?x=1'],
    'no host' => ['http:///path'],
    'whitespace for a host' => ['https:// app.example'],
    'a query' => ['https://app.example?x=1'],
    'a fragment' => ['https://app.example#top'],
    'userinfo' => ['https://admin@app.example'],
    'another scheme' => ['ftp://app.example'],
]);
