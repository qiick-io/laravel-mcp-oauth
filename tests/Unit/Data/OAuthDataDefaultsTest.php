<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Qiick\McpOAuth\Data\ClientInfo;
use Qiick\McpOAuth\Data\ConsentOptions;
use Qiick\McpOAuth\Data\ConsentPage;
use Qiick\McpOAuth\Data\ParsedRedirectUriData;
use Qiick\McpOAuth\Data\TokenResourceSelectionData;

it('defaults a client name to self-asserted and its callback to regular HTTPS', function (): void {
    $client = new ClientInfo('client', 'Client', 'app.example', ['https://app.example/return']);

    expect($client->nameIsSelfAsserted)->toBeTrue()
        ->and($client->isRedirectLoopback)->toBeFalse();
});

it('defaults consent to the regular authorization flow', function (): void {
    $page = new ConsentPage([], 'pending-auth', new ConsentOptions([], [], [], false, true));

    expect($page->isInstallationPairing)->toBeFalse();
});

it('defaults the parsed redirect to no path and a DNS host', function (): void {
    $redirect = new ParsedRedirectUriData('https', 'app.example');

    expect($redirect->path)->toBe('')
        ->and($redirect->isIpv6Literal)->toBeFalse();
});

it('returns only a typed selection from the token request attributes', function (): void {
    $request = new Request;
    $request->attributes->set(TokenResourceSelectionData::REQUEST_ATTRIBUTE, ['identifier' => 'https://app.example/mcp']);

    expect(TokenResourceSelectionData::from($request))->toBeNull();
});
