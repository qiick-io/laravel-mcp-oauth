<?php

declare(strict_types=1);

use Laravel\Passport\Client;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Red-first gates for adversarial #6: one canonical parse for every check.
 */
it('B2: isAllowedScheme refuses userinfo the same way registration does', function (string $uri): void {
    config()->set('mcp.custom_schemes', []);
    $guard = new RedirectUriGuard;

    expect($guard->isAcceptableForRegistration($uri))->toBeFalse()
        ->and($guard->isAllowedScheme($uri))->toBeFalse()
        ->and(fn () => $guard->hostOf($uri))->toThrow(InvalidArgumentException::class);
})->with([
    'user' => ['https://user@evil.com/cb'],
    'user:pass' => ['https://user:pass@evil.com/cb'],
    'pass only' => ['https://:secret@evil.com/cb'],
    'evil@good' => ['https://evil.com@good.example/cb'],
]);

it('B1: isAllowedScheme refuses backslash authority confusion', function (): void {
    config()->set('mcp.custom_schemes', []);
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['evil.com']));
    $uri = 'https://evil.com\\@good.example/cb';

    expect($guard->isAcceptableForRegistration($uri))->toBeFalse()
        ->and($guard->isAllowedScheme($uri))->toBeFalse()
        ->and(fn () => $guard->hostOf($uri))->toThrow(InvalidArgumentException::class);
});

it('N2: isAllowedScheme refuses fragments like registration and hostOf', function (): void {
    config()->set('mcp.custom_schemes', []);
    $guard = new RedirectUriGuard;
    $uri = 'https://app.example/cb#frag';

    expect($guard->isAcceptableForRegistration($uri))->toBeFalse()
        ->and($guard->isAllowedScheme($uri))->toBeFalse()
        ->and(fn () => $guard->hostOf($uri))->toThrow(InvalidArgumentException::class);
});

it('N1: registration refuses non-loopback http (RFC 8252)', function (): void {
    config()->set('mcp.custom_schemes', []);
    $guard = new RedirectUriGuard;

    expect($guard->isAllowedScheme('http://evil.example/cb'))->toBeFalse()
        ->and($guard->isAcceptableForRegistration('http://evil.example/cb'))->toBeFalse()
        ->and($guard->isAcceptableForRegistration('http://127.0.0.1/cb'))->toBeTrue()
        ->and($guard->isAcceptableForRegistration('http://localhost/cb'))->toBeTrue()
        ->and($guard->isAcceptableForRegistration('http://[::1]/cb'))->toBeTrue();
});

it('N8: leading-zero IPv4 octets are refused with a glibc-independent message', function (): void {
    $guard = new RedirectUriGuard;

    expect(fn () => $guard->normalizeHost('01.02.03.04'))
        ->toThrow(InvalidArgumentException::class, 'Leading-zero IPv4 octets are not allowed.')
        ->and($guard->isAcceptableForRegistration('https://01.02.03.04/cb'))->toBeFalse()
        ->and($guard->isAllowedScheme('https://01.02.03.04/cb'))->toBeFalse()
        ->and($guard->isAcceptableForRegistration('https://1.02.3.4/cb'))->toBeFalse();
});

it('canonical parse keeps scheme and host checks aligned for blocked hosts', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['evil.com']));
    $uri = 'https://evil.com@good.example/cb';

    expect($guard->isAllowedScheme($uri))->toBeFalse()
        ->and($guard->isAcceptableForRegistration($uri))->toBeFalse()
        ->and($guard->clientHasBlockedRedirectHost(
            tap(new Client, static function (Client $client) use ($uri): void {
                $client->setRawAttributes([
                    'redirect_uris' => json_encode([$uri], JSON_THROW_ON_ERROR),
                ]);
            }),
        ))->toBeTrue();
});
