<?php

declare(strict_types=1);

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Qiick\McpOAuth\ClientMetadataUriGuard;
use Qiick\McpOAuth\Http\Controllers\RegisterClientController;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * @return callable(string): bool
 */
function clientNameIsDisallowed(): callable
{
    $config = Mockery::mock(ConfigRepository::class);
    $config->shouldReceive('get')->andReturn(10_000)->byDefault();
    $controller = new RegisterClientController(
        new RedirectUriGuard(new BlockedHostCatalog([])),
        new ClientMetadataUriGuard,
        $config,
    );
    $method = new ReflectionMethod($controller, 'clientNameContainsDisallowedCharacters');
    $method->setAccessible(true);

    return static function (string $clientName) use ($method, $controller): bool {
        return (bool) $method->invoke(
            $controller,
            Request::create('/oauth/register', 'POST', ['client_name' => $clientName]),
        );
    };
}

it('allows emoji ZWJ sequences in client_name', function (): void {
    // Family emoji uses U+200D between code points.
    $isDisallowed = clientNameIsDisallowed();

    expect($isDisallowed('Team '."\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}"))->toBeFalse();
});

it('allows Persian ZWNJ in client_name', function (): void {
    $isDisallowed = clientNameIsDisallowed();

    expect($isDisallowed("می\u{200C}خواهم"))->toBeFalse();
});

it('still refuses bidi overrides and C0 controls', function (string $clientName): void {
    expect(clientNameIsDisallowed()($clientName))->toBeTrue();
})->with([
    'rlo' => "Good\u{202E}lacitirC",
    'lre' => "A\u{202A}B",
    'tab' => "Bad\tName",
    'nul' => "Bad\0Name",
]);
