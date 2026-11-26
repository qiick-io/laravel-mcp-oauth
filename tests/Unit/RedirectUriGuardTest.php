<?php

declare(strict_types=1);

use Laravel\Passport\Client;
use Qiick\McpOAuth\Data\BlockedRedirectHostData;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Qiick\McpOAuth\RedirectUriGuard;

it('refuses fragments and dangerous schemes even when listed as custom', function (): void {
    config()->set('mcp.custom_schemes', ['javascript', 'myapp']);
    $guard = new RedirectUriGuard;

    expect($guard->isAcceptableForRegistration('https://app.example/cb#frag'))->toBeFalse()
        ->and($guard->isAcceptableForRegistration('javascript:alert(1)'))->toBeFalse()
        ->and($guard->isAllowedScheme('javascript:alert(1)'))->toBeFalse()
        ->and($guard->isAllowedScheme('myapp://callback'))->toBeTrue();
});

it('accepts https and loopback http including IPv6', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->isAllowedScheme('https://app.example/cb'))->toBeTrue()
        ->and($guard->isAllowedScheme('http://127.0.0.1:8787/cb'))->toBeTrue()
        ->and($guard->isAllowedScheme('http://localhost/cb'))->toBeTrue()
        ->and($guard->isAllowedScheme('http://[::1]/cb'))->toBeTrue()
        ->and($guard->isAllowedScheme('http://evil.example/cb'))->toBeFalse()
        ->and($guard->isAcceptableForRegistration('http://[::1]/cb'))->toBeTrue();
});

it('refuses non-ASCII registered hosts', function (string $uri): void {
    $guard = new RedirectUriGuard;

    expect($guard->isAcceptableForRegistration($uri))->toBeFalse();
})->with([
    'unicode' => ['https://bücher.example/cb'],
    'fullwidth' => ['https://ａｐｐ.example/cb'],
]);

it('blocks exact hosts and subdomains but not sibling suffixes', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['app.test']));

    expect($guard->isHostBlocked('app.test'))->toBeTrue()
        ->and($guard->isHostBlocked('evil.app.test'))->toBeTrue()
        ->and($guard->isHostBlocked('notapp.test'))->toBeFalse()
        ->and($guard->isHostBlocked('app.test.evil'))->toBeFalse();
});

it('treats a host that does not normalise as blocked', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->isHostBlocked("bad host\0"))->toBeTrue();
});

it('stores display host as ASCII host or as the scheme for private-use URIs', function (): void {
    config()->set('mcp.custom_schemes', ['cursor']);
    $guard = new RedirectUriGuard;

    expect($guard->displayHostOf('https://App.Example./cb'))->toBe('app.example')
        ->and($guard->displayHostOf('cursor://auth'))->toBe('cursor');
});

it('normalises admin Unicode hosts to ASCII punycode', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->normalizeHost('bücher.example'))->toBe('xn--bcher-kva.example');
});

it('returns hostOf for ASCII hosts and null when the URI has no host', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->hostOf('https://App.Example./cb'))->toBe('app.example')
        ->and($guard->hostOf('cursor:opaque-path'))->toBeNull();
});

it('throws when hostOf sees a non-ASCII registered host', function (): void {
    $guard = new RedirectUriGuard;

    $guard->hostOf('https://bücher.example/cb');
})->throws(InvalidArgumentException::class);

it('throws when normalizeHost is empty or invalid', function (): void {
    $guard = new RedirectUriGuard;

    expect(fn () => $guard->normalizeHost(''))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $guard->normalizeHost(' '))->toThrow(InvalidArgumentException::class);
});

it('leaves IP literals alone without IDNA', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->normalizeHost('127.0.0.1'))->toBe('127.0.0.1')
        ->and($guard->normalizeHost('[::1]'))->toBe('::1')
        ->and($guard->normalizeHost('::1'))->toBe('::1');
});

it('flags a client when any redirect host is blocked or non-ASCII', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['evil.test']));
    $blocked = new Client;
    $blocked->forceFill(['redirect_uris' => ['https://evil.test/cb']]);
    $clean = new Client;
    $clean->forceFill(['redirect_uris' => ['https://app.example/cb']]);
    $nonAscii = new Client;
    $nonAscii->forceFill(['redirect_uris' => ['https://bücher.example/cb']]);

    expect($guard->clientHasBlockedRedirectHost($blocked))->toBeTrue()
        ->and($guard->clientHasBlockedRedirectHost($clean))->toBeFalse()
        ->and($guard->clientHasBlockedRedirectHost($nonAscii))->toBeTrue();
});

it('refuses registration URIs that cannot be parsed or lack a scheme', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->isAcceptableForRegistration('not a uri'))->toBeFalse()
        ->and($guard->isAcceptableForRegistration('/relative'))->toBeFalse()
        ->and($guard->isAllowedScheme('not a uri'))->toBeFalse()
        ->and($guard->isAllowedScheme('http://203.0.113.10/cb'))->toBeFalse();
});

it('blocks only the host itself for an exact-mode entry, and subdomains for the default mode', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog([
        new BlockedRedirectHostData('exact.test', shouldMatchSubdomains: false),
        'wide.test',
    ]));

    expect($guard->isHostBlocked('exact.test'))->toBeTrue()
        ->and($guard->isHostBlocked('EXACT.test.'))->toBeTrue()
        ->and($guard->isHostBlocked('app.exact.test'))->toBeFalse()
        ->and($guard->isHostBlocked('wide.test'))->toBeTrue()
        ->and($guard->isHostBlocked('app.wide.test'))->toBeTrue()
        ->and($guard->isHostBlocked('notwide.test'))->toBeFalse();
});

it('refuses relative and userinfo redirect URIs', function (string $redirectUri): void {
    expect((new RedirectUriGuard)->isAcceptableForRegistration($redirectUri))->toBeFalse();
})->with([
    'path only' => ['/callback'],
    'scheme-relative' => ['//app.example/callback'],
    'user without password' => ['https://user@app.example/callback'],
    'user and password' => ['https://user:secret@app.example/callback'],
]);

it('treats an empty query as no query, and any other query as different', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->areExactlyEqual('https://app.example/cb?', 'https://app.example/cb'))->toBeTrue()
        ->and($guard->areExactlyEqual('https://app.example/cb?x', 'https://app.example/cb'))->toBeFalse();
});

it('skips non-string custom schemes in the allow-list', function (): void {
    config()->set('mcp.custom_schemes', [5, null, 'MyApp']);

    expect((new RedirectUriGuard)->isAcceptableForRegistration('myapp://callback'))->toBeTrue()
        ->and((new RedirectUriGuard)->isAcceptableForRegistration('otherapp://callback'))->toBeFalse();
});

it('flags a stored redirect that no longer passes registration even when its host is not blocked', function (): void {
    $client = new Client;
    $client->setRawAttributes(['redirect_uris' => json_encode(['http://app.example/callback'], JSON_THROW_ON_ERROR)]);

    expect((new RedirectUriGuard(new BlockedHostCatalog([])))->clientHasBlockedRedirectHost($client))->toBeTrue();
});

it('refuses a host with only one IPv6 bracket', function (string $host): void {
    expect(fn () => (new RedirectUriGuard)->normalizeHost($host))->toThrow(InvalidArgumentException::class);
})->with(['[::1', '::1]']);

it('tells a native app redirect from a web one (RFC 8252 §7.1, §7.3)', function (string $redirectUri, bool $isNative): void {
    expect((new RedirectUriGuard)->isNativeRedirectUri($redirectUri))->toBe($isNative);
})->with([
    'loopback IPv4' => ['http://127.0.0.1:33418/callback', true],
    'loopback name' => ['http://LOCALHOST/callback', true],
    'loopback IPv6' => ['http://[::1]/callback', true],
    'private-use scheme' => ['cursor://anysphere.cursor-retrieval/oauth/callback', true],
    'https' => ['https://app.example/callback', false],
    'https on loopback' => ['https://127.0.0.1/callback', false],
    'http on a public host' => ['http://app.example/callback', false],
    'unparseable' => ['cursor://callback#fragment', false],
]);

it('tells a loopback http redirect from any other', function (string $redirectUri, bool $isLoopback): void {
    expect((new RedirectUriGuard)->isLoopbackRedirectUri($redirectUri))->toBe($isLoopback);
})->with([
    'IPv4' => ['http://127.0.0.1:33418/callback', true],
    'name' => ['http://LOCALHOST/callback', true],
    'IPv6' => ['http://[::1]/callback', true],
    'https on loopback' => ['https://127.0.0.1/callback', false],
    'http on a public host' => ['http://app.example/callback', false],
    'a private-use scheme' => ['cursor://callback', false],
    'unparseable' => ['http://127.0.0.1/callback#fragment', false],
]);
