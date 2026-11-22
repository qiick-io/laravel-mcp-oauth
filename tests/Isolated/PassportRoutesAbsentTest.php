<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Tests\Support\PassportBootedTestCase;

uses(PassportBootedTestCase::class);

/**
 * N1: with both providers registered, Passport must leave zero /oauth routes.
 */
it('registers no Passport oauth routes under ignoreRoutes', function (): void {
    expect(Passport::$registersRoutes)->toBeFalse()
        ->and(Passport::$deviceCodeGrantEnabled)->toBeFalse();

    $passportRouteNames = collect(Route::getRoutes())
        ->map(static fn ($route): string => (string) $route->getName())
        ->filter(static fn (string $name): bool => str_starts_with($name, 'passport.'))
        ->values()
        ->all();

    Artisan::call('route:list', ['--json' => true]);
    /** @var list<array{name?: string|null, uri?: string|null}> $routeListRows */
    $routeListRows = json_decode(Artisan::output(), true) ?: [];
    $passportRouteListRows = array_values(array_filter(
        $routeListRows,
        static function (array $row): bool {
            $name = (string) ($row['name'] ?? '');
            $uri = (string) ($row['uri'] ?? '');

            return str_starts_with($name, 'passport.') || str_contains($uri, 'oauth');
        },
    ));

    expect($passportRouteNames)->toBe([])
        ->and($passportRouteListRows)->toBe([]);
});
