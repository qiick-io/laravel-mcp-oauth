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

it('fails closed on client_name that is not valid UTF-8', function (string $clientName): void {
    expect(clientNameIsDisallowed()($clientName))->toBeTrue();
})->with([
    'overlong nul' => "A\xC0\x80B",
    'truncated sequence' => "A\xC3\x28B",
    'lone continuation byte' => "A\x80B",
]);

it('refuses line and paragraph separators in client_name', function (string $clientName): void {
    expect(clientNameIsDisallowed()($clientName))->toBeTrue();
})->with([
    'line separator' => "Good\u{2028}Name",
    'paragraph separator' => "Good\u{2029}Name",
]);

it('refuses Hangul fillers in client_name', function (string $clientName): void {
    expect(clientNameIsDisallowed()($clientName))->toBeTrue();
})->with([
    'hangul filler' => "Good\u{3164}Name",
    'only hangul fillers' => "\u{3164}\u{3164}",
    'halfwidth hangul filler' => "A\u{FFA0}B",
    'choseong filler' => "A\u{115F}B",
    'jungseong filler' => "A\u{1160}B",
]);

it('refuses a client_name with no visible character', function (string $clientName): void {
    expect(clientNameIsDisallowed()($clientName))->toBeTrue();
})->with([
    'spaces' => '   ',
    'no-break and ideographic spaces' => "\u{00A0}\u{3000}",
    'combining grapheme joiner' => "\u{034F}",
    'joiners only' => "\u{200D}\u{200C}",
]);

it('keeps accepting ordinary names with spaces and marks', function (string $clientName): void {
    expect(clientNameIsDisallowed()($clientName))->toBeFalse();
})->with([
    'plain' => 'Claude Desktop',
    'accented' => 'Café Désirée',
    'korean' => '클로드',
    'flag emoji' => "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}",
]);

/**
 * @param  array<string, mixed>  $registrationPayload
 */
function registrationNamesAreDisallowed(array $registrationPayload): bool
{
    $config = Mockery::mock(ConfigRepository::class);
    $config->shouldReceive('get')->andReturn(10_000)->byDefault();
    $controller = new RegisterClientController(
        new RedirectUriGuard(new BlockedHostCatalog([])),
        new ClientMetadataUriGuard,
        $config,
    );
    $method = new ReflectionMethod($controller, 'clientNameContainsDisallowedCharacters');

    return (bool) $method->invoke($controller, Request::create('/oauth/register', 'POST', $registrationPayload));
}

it('applies the policy to the name alias when client_name is absent or empty', function (array $registrationPayload): void {
    // resolveClientName() falls back to `name`, so the consent screen would show it.
    expect(registrationNamesAreDisallowed($registrationPayload))->toBeTrue();
})->with([
    'only name with bidi override' => [['name' => "Good\u{202E}lacitirC"]],
    'empty client_name then bad name' => [['client_name' => '', 'name' => "Good\u{202E}lacitirC"]],
    'non-string client_name then bad name' => [['client_name' => ['x'], 'name' => "A\u{2028}B"]],
]);

it('accepts a clean name alias', function (): void {
    expect(registrationNamesAreDisallowed(['name' => 'Claude Desktop']))->toBeFalse();
});

it('refuses names that render as nothing', function (string $clientName): void {
    expect(clientNameIsDisallowed()($clientName))->toBeTrue();
})->with([
    'blank braille pattern' => "\u{2800}",
    'variation selector 16 alone' => "\u{FE0F}",
    'lone combining mark' => "\u{0301}",
    'khmer inherent vowel' => "\u{17B5}",
    'spaces around blank braille' => " \u{2800} ",
]);
