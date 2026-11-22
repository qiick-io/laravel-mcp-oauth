<?php

declare(strict_types=1);

use Qiick\McpOAuth\ClientMetadataUriGuard;

it('accepts https to a public hostname', function (): void {
    $guard = new ClientMetadataUriGuard;

    expect($guard->isAcceptable('https://cdn.example.com/logo.png'))->toBeTrue()
        ->and($guard->isAcceptable('http://docs.example.com/'))->toBeTrue();
});

it('refuses loopback and private IP literals', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'ipv4 loopback' => 'http://127.0.0.1/logo.png',
    'ipv6 loopback' => 'https://[::1]/logo.png',
    'rfc1918 10' => 'https://10.0.0.1/logo.png',
    'rfc1918 192' => 'https://192.168.1.1/logo.png',
    'link-local' => 'https://169.254.169.254/latest',
    'ula ipv6' => 'https://[fd12:3456:789a::1]/logo.png',
]);

it('refuses dangerous schemes and fragments', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'javascript' => 'javascript:alert(1)',
    'fragment' => 'https://cdn.example.com/logo.png#x',
    'custom scheme' => 'cursor://cdn.example.com/logo',
    'userinfo' => 'https://user:pass@cdn.example.com/logo.png',
]);

it('accepts a public IPv4 literal over https', function (): void {
    expect((new ClientMetadataUriGuard)->isAcceptable('https://8.8.8.8/logo.png'))->toBeTrue();
});

it('normalises a trailing dot on the host', function (): void {
    expect((new ClientMetadataUriGuard)->isAcceptable('https://cdn.example.com./logo.png'))->toBeTrue();
});

it('refuses a percent-encoded host', function (): void {
    expect((new ClientMetadataUriGuard)->isAcceptable('https://cdn%2eexample.com/logo.png'))->toBeFalse();
});

it('refuses a backslash in the URI', function (): void {
    expect((new ClientMetadataUriGuard)->isAcceptable('https://cdn.example.com\\logo.png'))->toBeFalse();
});

it('refuses a hostless https URI', function (): void {
    expect((new ClientMetadataUriGuard)->isAcceptable('https:///logo.png'))->toBeFalse();
});
