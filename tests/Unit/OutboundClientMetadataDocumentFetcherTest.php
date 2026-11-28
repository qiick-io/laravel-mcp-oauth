<?php

declare(strict_types=1);

use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;
use Qiick\McpOAuth\Internal\ClientMetadataHostResolver;
use Qiick\McpOAuth\Internal\OutboundClientMetadataDocumentFetcher;
use Qiick\Outbound\Http\OutboundHttpStackData;
use Qiick\Outbound\Testing\FakeHostResolver;
use Qiick\Outbound\Testing\FakeOutboundHttpFactory;

const OUTBOUND_CIMD_URL = 'https://client.example/client.json';

function outboundFetcherWithPublicHost(Factory $factory): OutboundClientMetadataDocumentFetcher
{
    $factory->preventStrayRequests();
    $resolver = (new FakeHostResolver)->with('client.example', ['8.8.8.8']);

    return new OutboundClientMetadataDocumentFetcher(config(), OutboundHttpStackData::make($resolver, httpFactory: $factory));
}

it('refuses a later DNS answer with a private address before sending another request', function (): void {
    $resolver = (new FakeHostResolver)->queue('client.example', [['8.8.8.8'], ['8.8.8.8', '127.0.0.1']]);
    $factory = FakeOutboundHttpFactory::fake([OUTBOUND_CIMD_URL => Factory::response(['client_id' => OUTBOUND_CIMD_URL])]);
    $factory->preventStrayRequests();
    $fetcher = new OutboundClientMetadataDocumentFetcher(config(), OutboundHttpStackData::make(new ClientMetadataHostResolver($resolver), httpFactory: $factory));

    expect($fetcher->fetch(OUTBOUND_CIMD_URL)->status)->toBe(ClientMetadataFetchStatusEnum::Fetched)
        ->and($fetcher->fetch(OUTBOUND_CIMD_URL)->status)->toBe(ClientMetadataFetchStatusEnum::Invalid);
    $factory->assertSentCount(1);
});

it('reports empty DNS answers as transient without attempting a request', function (): void {
    $resolver = new ClientMetadataHostResolver(new FakeHostResolver);
    $factory = FakeOutboundHttpFactory::make();
    $factory->preventStrayRequests();
    $fetcher = new OutboundClientMetadataDocumentFetcher(config(), OutboundHttpStackData::make($resolver, httpFactory: $factory));

    expect($fetcher->fetch(OUTBOUND_CIMD_URL)->status)->toBe(ClientMetadataFetchStatusEnum::Unavailable);
    $factory->assertNothingSent();
});

it('does not follow a redirect even to the same origin', function (): void {
    $resolver = (new FakeHostResolver)->with('client.example', ['8.8.8.8']);
    $factory = FakeOutboundHttpFactory::fake([OUTBOUND_CIMD_URL => Factory::response('', 302, ['Location' => '/another.json'])]);
    $factory->preventStrayRequests();
    $fetcher = new OutboundClientMetadataDocumentFetcher(config(), OutboundHttpStackData::make($resolver, httpFactory: $factory));

    expect($fetcher->fetch(OUTBOUND_CIMD_URL)->status)->toBe(ClientMetadataFetchStatusEnum::Invalid);
    $factory->assertSentCount(1);
});

it('sends a conditional JSON request and reports the remaining cache lifetime', function (): void {
    $resolver = (new FakeHostResolver)->with('client.example', ['8.8.8.8']);
    $factory = FakeOutboundHttpFactory::fake([OUTBOUND_CIMD_URL => Factory::response('', 304, [
        'Cache-Control' => 'public, max-age=100',
        'Age' => '28',
        'ETag' => 'W/"one"',
    ])]);
    $factory->preventStrayRequests();
    $fetcher = new OutboundClientMetadataDocumentFetcher(config(), OutboundHttpStackData::make($resolver, httpFactory: $factory));

    $result = $fetcher->fetch(OUTBOUND_CIMD_URL, 'W/"one"');

    expect($result->status)->toBe(ClientMetadataFetchStatusEnum::NotModified)
        ->and($result->etag)->toBe('W/"one"')
        ->and($result->maxAgeSeconds)->toBe(72);
    $factory->assertSent(static fn (Request $request): bool => $request->hasHeader('If-None-Match', 'W/"one"')
        && $request->hasHeader('Accept', 'application/json'));
});

it('distinguishes temporary failures from invalid metadata responses', function (int $status, string $mediaType, string $body, ClientMetadataFetchStatusEnum $expectedStatus): void {
    $factory = FakeOutboundHttpFactory::fake([
        OUTBOUND_CIMD_URL => Factory::response($body, $status, ['Content-Type' => $mediaType]),
    ]);

    $result = outboundFetcherWithPublicHost($factory)->fetch(OUTBOUND_CIMD_URL, "invalid\r\nvalidator");

    expect($result->status)->toBe($expectedStatus)
        ->and($result->document)->toBe([]);
    $factory->assertSent(static fn (Request $request): bool => $request->method() === 'GET'
        && $request->hasHeader('Accept', 'application/json')
        && ! $request->hasHeader('If-None-Match'));
})->with([
    'unexpected 304 without a validator' => [304, 'application/json', '', ClientMetadataFetchStatusEnum::Invalid],
    'created instead of fetched' => [201, 'application/json', '{}', ClientMetadataFetchStatusEnum::Invalid],
    'remote limit' => [429, 'application/json', '{}', ClientMetadataFetchStatusEnum::Unavailable],
    'server error' => [503, 'text/html', '', ClientMetadataFetchStatusEnum::Unavailable],
    'unexpected media type' => [200, 'text/json', '{}', ClientMetadataFetchStatusEnum::Invalid],
    'malformed JSON' => [200, 'application/json', '{"broken":', ClientMetadataFetchStatusEnum::Invalid],
    'array instead of object' => [200, 'application/json', '[]', ClientMetadataFetchStatusEnum::Invalid],
    'excess nesting' => [200, 'application/json', str_repeat('{"nested":', 32).'null'.str_repeat('}', 32), ClientMetadataFetchStatusEnum::Invalid],
]);

it('returns JSON fields and preserves the meaning of cache headers', function (string $cacheControl, string $age, string $etag, ?int $expectedAge, bool $shouldCache, ?string $expectedEtag): void {
    $factory = FakeOutboundHttpFactory::fake([
        OUTBOUND_CIMD_URL => Factory::response('{"client_name":"Sample","4":"ignored"}', 200, [
            'Content-Type' => ' Application/Client+JSON ; charset=utf-8',
            'Cache-Control' => $cacheControl,
            'Age' => $age,
            'ETag' => $etag,
        ]),
    ]);

    $result = outboundFetcherWithPublicHost($factory)->fetch(OUTBOUND_CIMD_URL);

    expect($result->status)->toBe(ClientMetadataFetchStatusEnum::Fetched)
        ->and($result->document)->toBe(['client_name' => 'Sample'])
        ->and($result->maxAgeSeconds)->toBe($expectedAge)
        ->and($result->shouldCache)->toBe($shouldCache)
        ->and($result->etag)->toBe($expectedEtag);
})->with([
    'no headers' => ['', '', '', null, true, null],
    'no-store retains the stated age' => ['No-Store, max-age=45', '13', '"one"', 32, false, '"one"'],
    'private and already stale' => ['private, max-age=1', '9', 'not quoted', 0, false, null],
    'no-cache takes precedence' => ['no-cache, max-age=50', '3', '"two"', 0, true, '"two"'],
    'non-numeric age' => ['max-age=9', 'unknown', '"three"', 9, true, '"three"'],
    'validator fits the limit' => ['', '0', '"'.str_repeat('x', 253).'"', null, true, '"'.str_repeat('x', 253).'"'],
    'oversized validator' => ['', '0', '"'.str_repeat('x', 254).'"', null, true, null],
]);

it('rejects valid JSON beyond the configured byte budget', function (): void {
    config()->set('mcp-oauth.cimd.max_document_bytes', 12);
    $factory = FakeOutboundHttpFactory::fake([
        OUTBOUND_CIMD_URL => Factory::response('{"name":"valid but too long"}', 200, ['Content-Type' => 'application/json']),
    ]);

    expect(outboundFetcherWithPublicHost($factory)->fetch(OUTBOUND_CIMD_URL)->status)->toBe(ClientMetadataFetchStatusEnum::Invalid);
});

it('caps the connect timeout without changing the request timeout', function (int $timeout, int $expectedConnectTimeout): void {
    config()->set('mcp-oauth.cimd.timeout_seconds', $timeout);
    $factory = FakeOutboundHttpFactory::fake(static function (Request $request, array $options) use ($timeout, $expectedConnectTimeout): PromiseInterface {
        expect($request->method())->toBe('GET')
            ->and($options['timeout'])->toEqual($timeout)
            ->and($options['connect_timeout'])->toEqual($expectedConnectTimeout);

        return Factory::response([], 429);
    });

    expect(outboundFetcherWithPublicHost($factory)->fetch(OUTBOUND_CIMD_URL)->status)->toBe(ClientMetadataFetchStatusEnum::Unavailable);
})->with([[2, 2], [9, 3]]);

it('decodes an object just inside the JSON nesting limit', function (): void {
    $factory = FakeOutboundHttpFactory::fake([
        OUTBOUND_CIMD_URL => Factory::response(str_repeat('{"nested":', 31).'null'.str_repeat('}', 31), 200, ['Content-Type' => 'application/json']),
    ]);

    expect(outboundFetcherWithPublicHost($factory)->fetch(OUTBOUND_CIMD_URL)->status)->toBe(ClientMetadataFetchStatusEnum::Fetched);
});

it('refuses an HTTP URL when the caller uses the built-in HTTPS stack', function (): void {
    $fetcher = new OutboundClientMetadataDocumentFetcher(config());

    expect($fetcher->fetch('http://client.example/client.json')->status)->toBe(ClientMetadataFetchStatusEnum::Invalid);
});
