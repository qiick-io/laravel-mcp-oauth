<?php

declare(strict_types=1);

use Laravel\Passport\Client;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Qiick\McpOAuth\RedirectUriGuard;

it('refuses every dangerous scheme individually at registration and scheme check', function (string $uri): void {
    config()->set('mcp.custom_schemes', ['javascript', 'data', 'vbscript', 'file', 'cursor']);
    $guard = new RedirectUriGuard;

    expect($guard->isAcceptableForRegistration($uri))->toBeFalse()
        ->and($guard->isAllowedScheme($uri))->toBeFalse();
})->with([
    'javascript' => ['javascript:alert(1)'],
    'data' => ['data:text/html,hi'],
    'vbscript' => ['vbscript:msgbox(1)'],
    'file' => ['file:///etc/passwd'],
]);

it('accepts each loopback form including IPv6 bracketed [::1]', function (string $uri): void {
    $guard = new RedirectUriGuard;

    expect($guard->isAllowedScheme($uri))->toBeTrue()
        ->and($guard->isAcceptableForRegistration($uri))->toBeTrue();
})->with([
    '127.0.0.1' => ['http://127.0.0.1:8787/cb'],
    'localhost' => ['http://localhost/cb'],
    '::1' => ['http://[::1]:3000/cb'],
]);

it('refuses non-ASCII and lookalike registered hosts', function (string $uri): void {
    $guard = new RedirectUriGuard;

    expect($guard->isAcceptableForRegistration($uri))->toBeFalse();
})->with([
    'fullwidth letters' => ['https://ｅｖｉｌ.com/cb'],
    'combining accent' => ["https://e\u{0301}vil.com/cb"],
    'uppercase É' => ['https://Évil.com/cb'],
    'fullwidth subdomain' => ['https://sub.ｅｖｉｌ.com/cb'],
    'percent-encoded host' => ['https://%65vil.com/cb'],
    'userinfo user' => ['https://user@evil.com/cb'],
    'userinfo user:pass' => ['https://user:pass@evil.com/cb'],
    'userinfo pass only' => ['https://:secret@evil.com/cb'],
    'backslash' => ['https://evil.com\\@good.example/cb'],
]);

it('normalises a trailing dot and refuses zone ids that fail IDNA', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->normalizeHost('App.Example.'))->toBe('app.example')
        ->and(fn () => $guard->normalizeHost('fe80::1%eth0'))->toThrow(InvalidArgumentException::class);
});

it('uses nontransitional IDNA so sharp-s does not fold to ASCII ss', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->normalizeHost('faß.de'))->toBe('xn--fa-hia.de');
});

it('trims surrounding whitespace before normalising', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->normalizeHost('  App.Example.  '))->toBe('app.example');
});

it('accepts private-use schemes without a host and refuses empty custom scheme entries', function (): void {
    config()->set('mcp.custom_schemes', ['cursor', '', 12]);
    $guard = new RedirectUriGuard;

    expect($guard->isAcceptableForRegistration('cursor:opaque'))->toBeTrue()
        ->and($guard->isAcceptableForRegistration('cursor://'))->toBeTrue()
        ->and($guard->isAllowedScheme('cursor:opaque'))->toBeTrue()
        ->and($guard->isAllowedScheme('other:opaque'))->toBeFalse()
        ->and($guard->isAllowedScheme('12:opaque'))->toBeFalse()
        ->and($guard->displayHostOf('cursor:opaque'))->toBe('cursor')
        ->and($guard->displayHostOf('not-a-uri'))->toBe('')
        ->and($guard->displayHostOf('not a uri'))->toBe('');
});

it('fails closed when custom_schemes is not an array', function (): void {
    config()->set('mcp.custom_schemes', 'cursor');
    $guard = new RedirectUriGuard;

    expect($guard->isAllowedScheme('cursor://x'))->toBeFalse();
});

it('refuses http without a usable host', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->isAllowedScheme('http:'))->toBeFalse()
        ->and($guard->isAllowedScheme('http:///callback'))->toBeFalse()
        ->and($guard->isAllowedScheme('http://[not-an-ip]/cb'))->toBeFalse()
        ->and($guard->isAllowedScheme('//evil.com/cb'))->toBeFalse();
});

it('refuses http hosts that fail IDNA STD3 (underscore) via isAllowedScheme alone', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->isAllowedScheme('http://ev_il.com'))->toBeFalse()
        ->and($guard->isAcceptableForRegistration('http://ev_il.com/cb'))->toBeFalse();
});

it('refuses hostless http(s) redirect URIs that browsers resolve onto the path host', function (string $uri): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['evil.com']));

    expect($guard->isAcceptableForRegistration($uri))->toBeFalse()
        ->and($guard->isAllowedScheme($uri))->toBeFalse()
        ->and(fn () => $guard->hostOf($uri))->toThrow(InvalidArgumentException::class);
})->with([
    'triple slash' => ['https:///evil.com/cb'],
    'single slash' => ['https:/evil.com/cb'],
    'scheme only' => ['https:evil.com/cb'],
    'quadruple slash' => ['https:////evil.com/cb'],
    'http triple slash' => ['http:///127.0.0.1/cb'],
]);

it('canonicalises IPv6 and unmaps ::ffff so alternate spellings hit the same block', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['2001:db8::1', '1.2.3.4']));

    expect($guard->isHostBlocked('2001:0db8:0:0::1'))->toBeTrue()
        ->and($guard->isHostBlocked('[2001:0db8:0:0::1]'))->toBeTrue()
        ->and($guard->isHostBlocked('::ffff:1.2.3.4'))->toBeTrue()
        ->and($guard->isHostBlocked('[::ffff:1.2.3.4]'))->toBeTrue()
        ->and($guard->isHostBlocked('[::ffff:0:1.2.3.4]'))->toBeTrue()
        ->and($guard->isHostBlocked('[::1.2.3.4]'))->toBeTrue()
        ->and($guard->isHostBlocked('[64:ff9b::1.2.3.4]'))->toBeTrue()
        ->and($guard->normalizeHost('2001:0db8:0:0::1'))->toBe('2001:db8::1')
        ->and($guard->normalizeHost('::ffff:1.2.3.4'))->toBe('1.2.3.4')
        ->and($guard->normalizeHost('::ffff:0:1.2.3.4'))->toBe('1.2.3.4')
        ->and($guard->normalizeHost('::1.2.3.4'))->toBe('1.2.3.4')
        ->and($guard->normalizeHost('64:ff9b::1.2.3.4'))->toBe('1.2.3.4');
});

it('refuses non-dotted-decimal IPv4 spellings that WHATWG would still parse', function (string $host): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['1.2.3.4']));

    expect(fn () => $guard->normalizeHost($host))->toThrow(InvalidArgumentException::class)
        ->and($guard->isAcceptableForRegistration('https://'.$host.'/cb'))->toBeFalse()
        ->and($guard->isHostBlocked($host))->toBeTrue();
})->with([
    'integer' => ['16909060'],
    'octal octets' => ['01.02.03.04'],
    'short form' => ['127.1'],
    'hex' => ['0x7f000001'],
]);

it('refuses leading-zero IPv4 octets as forbidden notation (glibc-safe)', function (): void {
    $guard = new RedirectUriGuard;

    // Without the leading-zero check, glibc inet_pton rejects these and IDNA
    // would accept them as ordinary hostnames.
    expect(fn () => $guard->normalizeHost('01.02.03.04'))->toThrow(InvalidArgumentException::class)
        ->and($guard->isAcceptableForRegistration('https://01.02.03.04/cb'))->toBeFalse()
        ->and($guard->isAllowedScheme('https://01.02.03.04/cb'))->toBeFalse();
});

it('allows domains that contain 0x but are not hex IPv4 labels', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->normalizeHost('0xproject.io'))->toBe('0xproject.io')
        ->and($guard->isAcceptableForRegistration('https://0xproject.io/cb'))->toBeTrue();
});

it('flags clients whose stored redirect URIs fail registration rules', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog([]));
    $backslash = new Client;
    $backslash->setRawAttributes([
        'redirect_uris' => json_encode(['https://evil.com\\@good.com/cb'], JSON_THROW_ON_ERROR),
    ]);
    $hostless = new Client;
    $hostless->setRawAttributes([
        'redirect_uris' => json_encode(['https:///evil.com/cb'], JSON_THROW_ON_ERROR),
    ]);

    expect($guard->clientHasBlockedRedirectHost($backslash))->toBeTrue()
        ->and($guard->clientHasBlockedRedirectHost($hostless))->toBeTrue();
});

it('refuses registration for hosts that fail normalisation after ASCII check', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->isAcceptableForRegistration('https://./cb'))->toBeFalse()
        ->and($guard->isAcceptableForRegistration('https://../cb'))->toBeFalse();
});

it('skips empty blocked-host rows and continues past hosts that cannot normalise', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['', "bad\0host", 'evil.test', '']));

    expect($guard->isHostBlocked('evil.test'))->toBeTrue()
        ->and($guard->isHostBlocked('ok.example'))->toBeFalse()
        ->and($guard->isHostBlocked(''))->toBeTrue();
});

it('ignores non-string redirect URIs then still detects a later blocked host', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog(['evil.test']));
    $mixed = new Client;
    $mixed->setRawAttributes([
        'redirect_uris' => json_encode([null, 12, 'https://evil.test/cb'], JSON_THROW_ON_ERROR),
    ]);
    $notArray = new Client;
    $notArray->setRawAttributes(['redirect_uris' => null, 'redirect' => '']);

    expect($guard->clientHasBlockedRedirectHost($mixed))->toBeTrue()
        ->and($guard->clientHasBlockedRedirectHost($notArray))->toBeFalse();
});

it('displayHostOf returns empty when the canonical parse refuses the URI', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->displayHostOf('https://Évil.com/cb'))->toBe('')
        ->and($guard->displayHostOf('https://user@evil.com/cb'))->toBe('')
        ->and($guard->displayHostOf('http://127.0.0.1/cb'))->toBe('127.0.0.1')
        ->and($guard->displayHostOf('http://localhost/cb'))->toBe('localhost');
});

it('hostOf returns null for empty host on private-use schemes and throws on unparseable URIs', function (): void {
    $guard = new RedirectUriGuard;

    expect($guard->hostOf('cursor://'))->toBeNull()
        ->and(fn () => $guard->hostOf('not a uri'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $guard->hostOf('https:///evil.com/cb'))->toThrow(InvalidArgumentException::class);
});

it('forbids parse_url anywhere under src including string callables', function (): void {
    $sourceRoot = dirname(__DIR__, 2).'/src';
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sourceRoot));

    foreach ($iterator as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());
        expect($contents)->not->toMatch('/\bparse_url\s*\(/')
            ->and($contents)->not->toContain("'parse_url'")
            ->and($contents)->not->toContain('"parse_url"');
    }
});
