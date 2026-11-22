<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Qiick\McpOAuth\ClientThrottleKey;

it('keys IPv4 as the address itself', function (): void {
    $request = Request::create('/', 'GET', server: ['REMOTE_ADDR' => '203.0.113.10']);

    expect(ClientThrottleKey::fromRequest($request))->toBe('203.0.113.10');
});

it('unmaps IPv4-mapped, IPv4-compatible and NAT64 addresses to the embedded IPv4', function (string $address, string $expected): void {
    $request = Request::create('/', 'GET', server: ['REMOTE_ADDR' => $address]);

    expect(ClientThrottleKey::fromRequest($request))->toBe($expected);
})->with([
    'mapped' => ['::ffff:203.0.113.10', '203.0.113.10'],
    'translated' => ['::ffff:0:203.0.113.10', '203.0.113.10'],
    'compatible' => ['::203.0.113.10', '203.0.113.10'],
    'nat64' => ['64:ff9b::203.0.113.10', '203.0.113.10'],
    'nat64 local /48' => ['64:ff9b:1::203.0.113.10', '203.0.113.10'],
]);

it('does not treat ::/127 as an IPv4-compatible address', function (string $address): void {
    $request = Request::create('/', 'GET', server: ['REMOTE_ADDR' => $address]);

    expect(ClientThrottleKey::fromRequest($request))->toStartWith('v6:');
})->with([
    'unspecified' => ['::'],
    'loopback' => ['::1'],
]);

it('keys other IPv6 by the exact /64 network prefix', function (): void {
    $inNetwork = Request::create('/', 'GET', server: ['REMOTE_ADDR' => '2001:db8:85a3::8a2e:370:7334']);
    $sameNetwork = Request::create('/', 'GET', server: ['REMOTE_ADDR' => '2001:db8:85a3::1']);
    $otherNetwork = Request::create('/', 'GET', server: ['REMOTE_ADDR' => '2001:db8:85a4::1']);

    $expectedPrefix = 'v6:'.bin2hex(substr((string) inet_pton('2001:db8:85a3::1'), 0, 8));

    expect(ClientThrottleKey::fromRequest($inNetwork))->toBe($expectedPrefix)
        ->and(ClientThrottleKey::fromRequest($sameNetwork))->toBe($expectedPrefix)
        ->and(ClientThrottleKey::fromRequest($otherNetwork))->not->toBe($expectedPrefix)
        ->and(ClientThrottleKey::fromRequest($otherNetwork))->toStartWith('v6:');
});

it('returns the raw string when the address cannot be packed', function (): void {
    $request = Request::create('/', 'GET', server: ['REMOTE_ADDR' => 'not-an-ip']);

    // Request::ip() may normalise; force an unparseable value via a subclass.
    $request->server->set('REMOTE_ADDR', 'not-an-ip');

    expect(ClientThrottleKey::fromRequest($request))->toBeString();
});

it('ignores X-Forwarded-For when proxies are not trusted', function (): void {
    $request = Request::create('/', 'GET', server: [
        'REMOTE_ADDR' => '203.0.113.10',
        'HTTP_X_FORWARDED_FOR' => '198.51.100.1',
    ]);

    expect(ClientThrottleKey::fromRequest($request))->toBe('203.0.113.10');
});
