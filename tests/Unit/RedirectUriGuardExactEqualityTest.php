<?php

declare(strict_types=1);

use Laravel\Passport\Client;
use Qiick\McpOAuth\RedirectUriGuard;

it('treats scheme and host case as equal under the canonical parse', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual(
        'https://App.Example/callback',
        'HTTPS://app.example/callback',
    ))->toBeTrue();
});

it('refuses equality when only the host differs', function (): void {
    $guard = new RedirectUriGuard;

    // Survives BooleanAndToBooleanOr on the host conjunct (evil ≈ app).
    expect($guard->areExactlyEqual(
        'https://app.example/callback',
        'https://evil.example/callback',
    ))->toBeFalse();
});

it('refuses equality when only the scheme differs', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual(
        'http://localhost/callback',
        'https://localhost/callback',
    ))->toBeFalse();
});

it('refuses equality when only the path differs', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual(
        'https://app.example/callback',
        'https://app.example/other',
    ))->toBeFalse();
});

it('refuses equality when the query string differs', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual(
        'https://app.example/callback?x=1',
        'https://app.example/callback?x=2',
    ))->toBeFalse();
});

it('refuses equality when only the port differs', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual(
        'http://127.0.0.1:8080/callback',
        'http://127.0.0.1:9090/callback',
    ))->toBeFalse();
});

it('treats identical ports and query strings as equal', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual(
        'http://127.0.0.1:8080/callback?x=1',
        'http://127.0.0.1:8080/callback?x=1',
    ))->toBeTrue()
        ->and($guard->areExactlyEqual(
            'https://app.example/callback',
            'https://app.example/callback',
        ))->toBeTrue();
});

it('refuses equality when only one side has a query', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual(
        'https://app.example/callback',
        'https://app.example/callback?x=1',
    ))->toBeFalse();
});

it('returns false when either URI fails the canonical parse', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual('https://app.example/cb#frag', 'https://app.example/cb'))->toBeFalse()
        ->and($guard->areExactlyEqual('https://app.example/cb', 'https://app.example/cb#frag'))->toBeFalse();
});

it('matches a client redirect_uri only under exact canonical equality', function (): void {
    $guard = new RedirectUriGuard;
    $client = new Client;
    $client->forceFill([
        'redirect_uris' => ['https://app.example/callback'],
    ]);

    expect($guard->clientHasExactRedirectUri($client, 'HTTPS://App.Example/callback'))->toBeTrue()
        ->and($guard->clientHasExactRedirectUri($client, 'https://app.example/other'))->toBeFalse()
        ->and($guard->clientHasExactRedirectUri($client, 'https://app.example/callback?x=1'))->toBeFalse();
});
