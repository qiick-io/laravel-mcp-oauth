<?php

declare(strict_types=1);

use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Qiick\McpOAuth\Enums\ClientMetadataFetchStatusEnum;
use Qiick\McpOAuth\Internal\ClientMetadataHostResolver;
use Qiick\McpOAuth\Internal\OutboundClientMetadataDocumentFetcher;
use Qiick\Outbound\Http\OutboundHttpStackData;
use Qiick\Outbound\Testing\FakeHostResolver;
use Qiick\Outbound\Testing\FakeOutboundHttpFactory;

const OUTBOUND_CIMD_URL = 'https://client.example/client.json';

it('refuses a later DNS answer with a private address before sending another request', function (): void {
    $resolver = (new FakeHostResolver)->queue('client.example', [['8.8.8.8'], ['8.8.8.8', '127.0.0.1']]);
    $factory = FakeOutboundHttpFactory::fake([OUTBOUND_CIMD_URL => Factory::response(['client_id' => OUTBOUND_CIMD_URL])]);
    $factory->preventStrayRequests();
    $fetcher = new OutboundClientMetadataDocumentFetcher(config(), OutboundHttpStackData::make($resolver, httpFactory: $factory));

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
