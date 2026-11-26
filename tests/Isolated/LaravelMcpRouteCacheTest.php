<?php

declare(strict_types=1);

use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\Tests\Support\PackageTestCase;

uses(PackageTestCase::class);

/**
 * S13 with `php artisan route:cache`: cached routes are restored after every
 * provider has booted, so a boot-time look at the routes misses laravel/mcp's
 * Host-derived OAuth routes. The package checks again once the router serves
 * its first request, when the routes are final.
 */
function cacheRoutesBesideLaravelMcp(PackageTestCase $testCase): void
{
    (new ReflectionMethod($testCase, 'defineCacheRoutes'))->invoke($testCase, <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;

Route::get('.well-known/oauth-protected-resource/{path}', fn () => 'host-derived')->where('path', '.*')->name('mcp.oauth.protected-resource.nested');
Route::get('ping', fn () => 'pong');
PHP);
}

it('refuses to serve beside laravel/mcp OAuth routes restored from the route cache', function (): void {
    cacheRoutesBesideLaravelMcp($this);
    config()->set('mcp-oauth.enabled', true);

    $this->withoutExceptionHandling();

    expect(fn () => $this->get('/ping'))
        ->toThrow(InvalidMcpOAuthConfigException::class, 'mcp.oauth.protected-resource.nested');
});

it('serves from the route cache as before while OAuth is off', function (): void {
    cacheRoutesBesideLaravelMcp($this);

    $this->get('/ping')->assertOk()->assertSee('pong');
});
