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

it('refuses internal hostnames by name', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'localhost' => 'http://localhost/',
    'localhost trailing dot' => 'https://localhost./x',
    'localhost upper case with port' => 'http://LOCALHOST:6379/',
    'localhost subdomain' => 'https://app.localhost/logo.png',
    'gce metadata' => 'https://metadata.google.internal/',
    'internal tld' => 'https://vault.corp.internal/logo.png',
    'mdns local' => 'https://printer.local/logo.png',
    'single label metadata' => 'https://metadata/',
    'single label instance-data' => 'https://instance-data/',
]);

it('refuses every alternative IPv4 spelling of loopback', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'short form' => 'https://127.1/',
    'integer' => 'https://2130706433/',
    'hex integer' => 'https://0x7f000001/',
    'octal octet' => 'https://0177.0.0.1/',
    'octal integer' => 'https://017700000001/',
]);

it('refuses IPv6 literals that embed an IPv4 address', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'nat64 well-known to metadata' => 'https://[64:ff9b::a9fe:a9fe]/',
    'nat64 local-use' => 'https://[64:ff9b:1::a00:1]/',
    'ipv4-translated' => 'https://[::ffff:0:a00:1]/',
    'ipv4-mapped loopback' => 'https://[::ffff:127.0.0.1]/',
    'ipv4-mapped public' => 'https://[::ffff:8.8.8.8]/',
    'nat64 public' => 'https://[64:ff9b::808:808]/',
    '6to4 loopback' => 'https://[2002:7f00:1::]/',
    '6to4 public' => 'https://[2002:808:808::1]/',
]);

it('refuses Unicode hosts that normalise to internal hosts', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'circled l' => 'https://ⓛocalhost/',
    'fullwidth' => 'https://ｌｏｃａｌｈｏｓｔ/',
    'ideographic dots' => 'https://127。0。0。1/',
]);

it('refuses shared, benchmarking, IETF and multicast ranges', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'cgnat low' => 'https://100.64.0.1/',
    'cgnat high' => 'https://100.127.255.254/',
    'benchmarking' => 'https://198.18.0.1/',
    'benchmarking upper' => 'https://198.19.255.1/',
    'ietf protocol assignments' => 'https://192.0.0.1/',
    'ipv4 multicast' => 'https://224.0.0.1/',
    'ipv4 multicast upper' => 'https://239.255.255.250/',
    'ipv6 multicast' => 'https://[ff02::1]/',
]);

it('keeps accepting public addresses next to the refused ranges', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeTrue();
})->with([
    'below cgnat' => 'https://100.63.255.255/',
    'above cgnat' => 'https://100.128.0.1/',
    'below benchmarking' => 'https://198.17.255.255/',
    'above benchmarking' => 'https://198.20.0.1/',
    'next to ietf block' => 'https://192.0.1.1/',
    'below multicast' => 'https://223.255.255.255/',
    'public ipv6' => 'https://[2606:4700:4700::1111]/',
    'two-label host' => 'https://example.com/',
    'host ending in localhost-like label' => 'https://notlocalhost.example/',
]);

it('never matches an IPv4 address against an IPv6 range', function (string $uri): void {
    // 32.2.x.x shares its first 16 bits with 2002::/16, 255.x with ff00::/8.
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeTrue();
})->with([
    'bits of 6to4 prefix' => 'https://32.2.1.1/',
]);

it('refuses the last address of each extra range', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'ietf block end' => 'https://192.0.0.255/',
    'ipv6 multicast end' => 'https://[ffff::1]/',
    '6to4 end' => 'https://[2002:ffff:ffff::1]/',
]);

it('accepts the addresses just outside the IPv6 extra ranges', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeTrue();
})->with([
    'below multicast' => 'https://[feff::1]/',
    'below 6to4' => 'https://[2001:4860::8888]/',
    'above 6to4' => 'https://[2003::1]/',
]);

it('refuses Teredo, documentation, discard and old relay ranges', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'teredo' => 'https://[2001::1]/',
    'teredo with embedded address' => 'https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/',
    'ipv6 documentation' => 'https://[2001:db8::1]/',
    'test-net-1' => 'https://192.0.2.10/',
    'test-net-2' => 'https://198.51.100.10/',
    'test-net-3' => 'https://203.0.113.10/',
    'ipv6 discard' => 'https://[100::1]/',
    'former 6to4 relay' => 'https://192.88.99.1/',
]);

it('refuses home-network names', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'lan' => 'https://router.lan/logo.png',
    'home.arpa' => 'https://nas.home.arpa/logo.png',
    'home.arpa itself' => 'https://home.arpa/',
]);

it('keeps accepting public neighbours of the new ranges', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeTrue();
})->with([
    'next to teredo' => 'https://[2001:1::1]/',
    'next to documentation' => 'https://[2001:db9::1]/',
    'next to test-net-3' => 'https://203.0.114.1/',
    'arpa-like public name' => 'https://home.arpa.example/',
    'lan as a label' => 'https://lan.example.com/',
]);

it('refuses the top of each documentation and transition range', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeFalse();
})->with([
    'teredo top' => 'https://[2001:0:ffff:ffff::1]/',
    'ipv6 documentation top' => 'https://[2001:db8:ffff:ffff::1]/',
    'ipv6 discard top' => 'https://[100::ffff:ffff:ffff:ffff]/',
    'test-net-1 top' => 'https://192.0.2.255/',
    'test-net-2 top' => 'https://198.51.100.255/',
    'test-net-3 top' => 'https://203.0.113.255/',
    'former relay top' => 'https://192.88.99.255/',
]);

it('accepts the block just below or beside each documentation and transition range', function (string $uri): void {
    expect((new ClientMetadataUriGuard)->isAcceptable($uri))->toBeTrue();
})->with([
    'beside ipv6 discard' => 'https://[100:0:0:1::1]/',
    'beside test-net-1' => 'https://192.0.3.1/',
    'beside test-net-2' => 'https://198.51.101.1/',
    'beside test-net-3' => 'https://203.0.112.1/',
    'beside former relay' => 'https://192.88.98.1/',
]);
