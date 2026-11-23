<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Qiick\McpOAuth\McpOAuthRoutes;

it('registers DCR when no passport routes exist', function (): void {
    McpOAuthRoutes::register();

    expect(Route::has('mcp.oauth.register'))->toBeTrue();
});

it('ignores unnamed and non-passport named routes', function (): void {
    Route::get('unnamed', fn () => 'x');
    Route::get('named', fn () => 'x')->name('app.dashboard');

    expect(fn () => McpOAuthRoutes::register())->not->toThrow(LogicException::class);
});

it('throws when any passport-prefixed route name is already registered', function (): void {
    Route::get('oauth/authorize', fn () => 'x')->name('passport.authorizations.authorize');

    try {
        McpOAuthRoutes::register();
        expect(false)->toBeTrue('expected LogicException');
    } catch (LogicException $exception) {
        expect($exception->getMessage())->toBe(
            'McpOAuthRoutes::register() refuses to run beside foreign Passport route [passport.authorizations.authorize]. '
            .'This package is not an adopter for Signaculum-style Passport IdPs (design §3.3).',
        );
    }
});

it('keeps scanning after a non-passport named route for a later passport name', function (): void {
    Route::get('first', fn () => 'x')->name('app.first');
    Route::get('second', fn () => 'x')->name('passport.token');

    expect(fn () => McpOAuthRoutes::register())
        ->toThrow(LogicException::class, 'passport.token');
});
