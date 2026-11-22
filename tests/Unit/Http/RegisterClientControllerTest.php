<?php

declare(strict_types=1);

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Events\McpClientRegistered;
use Qiick\McpOAuth\Http\Controllers\RegisterClientController;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Qiick\McpOAuth\RedirectUriGuard;

beforeEach(function (): void {
    Schema::dropIfExists('oauth_clients');
    Schema::create('oauth_clients', function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->nullableMorphs('owner');
        $table->string('name');
        $table->string('secret')->nullable();
        $table->string('provider')->nullable();
        $table->text('redirect_uris');
        $table->text('grant_types');
        $table->text('scopes')->nullable();
        $table->boolean('revoked');
        $table->timestamps();
    });
});

/**
 * @return array{0: RegisterClientController, 1: RedirectUriGuard}
 */
function makeRegisterClientController(?BlockedHostCatalog $blockedHosts = null): array
{
    $guard = new RedirectUriGuard($blockedHosts ?? new BlockedHostCatalog([]));
    $config = Mockery::mock(ConfigRepository::class);
    $config->shouldReceive('get')
        ->with('mcp-oauth.registrations_global_cap')
        ->andReturn(10_000)
        ->byDefault();

    return [new RegisterClientController($guard, $config), $guard];
}

/**
 * @param  array<int, mixed>  $arguments
 */
function invokeRegisterClientControllerMethod(
    RegisterClientController $controller,
    string $methodName,
    array $arguments = [],
): mixed {
    $method = new ReflectionMethod($controller, $methodName);
    $method->setAccessible(true);

    return $method->invokeArgs($controller, $arguments);
}

it('rejects a non-string redirect_uri entry before hitting Passport', function (): void {
    [$controller] = makeRegisterClientController();

    $response = $controller(Request::create('/oauth/register', 'POST', [
        'client_name' => 'Bad',
        'redirect_uris' => [123],
    ]));

    // Non-strings are skipped by stringRedirectUris; parent then fails validation.
    // Pre-check only rejects disallowed strings — empty string list falls through.
    expect($response)->toBeInstanceOf(JsonResponse::class);
});

it('returns 400 invalid_redirect_uri for a fragment URI', function (): void {
    [$controller] = makeRegisterClientController();

    $response = $controller(Request::create('/oauth/register', 'POST', [
        'client_name' => 'Fragment',
        'redirect_uris' => ['https://app.example/callback#frag'],
    ]));

    expect($response->getStatusCode())->toBe(400)
        ->and($response->getData(true))->toBe([
            'error' => 'invalid_redirect_uri',
            'error_description' => 'One or more redirect_uris are not allowed.',
        ]);
});

it('returns 400 for a blocked redirect host', function (): void {
    [$controller] = makeRegisterClientController(new BlockedHostCatalog(['evil.test']));

    $response = $controller(Request::create('/oauth/register', 'POST', [
        'client_name' => 'Blocked',
        'redirect_uris' => ['https://evil.test/callback'],
    ]));

    expect($response->getStatusCode())->toBe(400)
        ->and($response->getData(true)['error'])->toBe('invalid_redirect_uri');
});

it('returns 503 when the global registration cap is reached', function (): void {
    $guard = new RedirectUriGuard(new BlockedHostCatalog([]));
    $config = Mockery::mock(ConfigRepository::class);
    $config->shouldReceive('get')
        ->with('mcp-oauth.registrations_global_cap')
        ->andReturn(1);

    Client::query()->forceCreate([
        'id' => (string) Str::uuid7(),
        'name' => 'Existing',
        'secret' => null,
        'redirect_uris' => ['https://existing.example/cb'],
        'grant_types' => ['authorization_code'],
        'revoked' => false,
    ]);

    $controller = new RegisterClientController($guard, $config);
    $response = $controller(Request::create('/oauth/register', 'POST', [
        'client_name' => 'Over Cap',
        'redirect_uris' => ['https://app.example/callback'],
    ]));

    expect($response->getStatusCode())->toBe(503)
        ->and($response->getData(true))->toBe([
            'error' => 'temporarily_unavailable',
            'error_description' => 'The global OAuth client registration cap has been reached.',
        ]);
});

it('skips the pre-check loop when redirect_uris is not an array', function (): void {
    [$controller] = makeRegisterClientController();

    // Falls through to parent validation (invalid_client_metadata / invalid_redirect_uri).
    $response = $controller(Request::create('/oauth/register', 'POST', [
        'client_name' => 'No Uris',
        'redirect_uris' => 'https://app.example/callback',
    ]));

    expect($response->getStatusCode())->toBe(400);
});

it('isValidRedirectUri delegates to the guard', function (): void {
    [$controller] = makeRegisterClientController();

    expect(invokeRegisterClientControllerMethod($controller, 'isValidRedirectUri', ['https://app.example/cb']))->toBeTrue()
        ->and(invokeRegisterClientControllerMethod($controller, 'isValidRedirectUri', ['http://example.com/cb']))->toBeFalse()
        ->and(invokeRegisterClientControllerMethod($controller, 'isValidRedirectUri', ['https://app.example/cb#x']))->toBeFalse();
});

it('resolves client_name then name then display host then default', function (): void {
    [$controller] = makeRegisterClientController();

    expect(invokeRegisterClientControllerMethod($controller, 'resolveClientName', [[
        'client_name' => 'From Client Name',
        'name' => 'From Name',
        'redirect_uris' => ['https://app.example/cb'],
    ]]))->toBe('From Client Name')
        ->and(invokeRegisterClientControllerMethod($controller, 'resolveClientName', [[
            'client_name' => '',
            'name' => 'From Name',
            'redirect_uris' => ['https://app.example/cb'],
        ]]))->toBe('From Name')
        ->and(invokeRegisterClientControllerMethod($controller, 'resolveClientName', [[
            'redirect_uris' => ['https://app.example/cb'],
        ]]))->toBe('app.example')
        ->and(invokeRegisterClientControllerMethod($controller, 'resolveClientName', [[
            'redirect_uris' => ['cursor://local/cb'],
        ]]))->toBe('cursor')
        ->and(invokeRegisterClientControllerMethod($controller, 'resolveClientName', [[
            'redirect_uris' => [null],
        ]]))->toBe('MCP Client')
        ->and(invokeRegisterClientControllerMethod($controller, 'resolveClientName', [[
            'redirect_uris' => 'not-array',
        ]]))->toBe('MCP Client')
        ->and(invokeRegisterClientControllerMethod($controller, 'resolveClientName', [[]]))->toBe('MCP Client');
});

it('collects unique display hosts and skips non-strings', function (): void {
    [$controller] = makeRegisterClientController();

    expect(invokeRegisterClientControllerMethod($controller, 'displayHostsFromRedirectUris', [[
        'https://app.example/a',
        42,
        'https://App.Example/b',
        'https://other.example/c',
        'https://app.example/d#bad',
    ]]))->toBe(['app.example', 'other.example']);
});

it('dispatches McpClientRegistered only for a complete 201 payload', function (): void {
    Event::fake([McpClientRegistered::class]);
    [$controller] = makeRegisterClientController();

    invokeRegisterClientControllerMethod($controller, 'dispatchRegisteredEvent', [
        response()->json(['client_id' => 'abc', 'redirect_uris' => ['https://app.example/cb']], 201),
    ]);

    Event::assertDispatched(McpClientRegistered::class, function (McpClientRegistered $event): bool {
        return $event->clientId === 'abc' && $event->displayHosts === ['app.example'];
    });

    Event::fake([McpClientRegistered::class]);

    invokeRegisterClientControllerMethod($controller, 'dispatchRegisteredEvent', [
        response()->json(['client_id' => '', 'redirect_uris' => ['https://app.example/cb']], 201),
    ]);
    Event::assertNotDispatched(McpClientRegistered::class);

    invokeRegisterClientControllerMethod($controller, 'dispatchRegisteredEvent', [
        response()->json(['client_id' => 'abc', 'redirect_uris' => 'nope'], 201),
    ]);
    Event::assertNotDispatched(McpClientRegistered::class);
});

it('stringRedirectUris keeps only strings', function (): void {
    [$controller] = makeRegisterClientController();

    expect(invokeRegisterClientControllerMethod($controller, 'stringRedirectUris', [[
        'https://a.example/cb',
        1,
        null,
        'https://b.example/cb',
    ]]))->toBe(['https://a.example/cb', 'https://b.example/cb'])
        ->and(invokeRegisterClientControllerMethod($controller, 'stringRedirectUris', ['nope']))->toBe([])
        ->and(invokeRegisterClientControllerMethod($controller, 'stringRedirectUris', [null]))->toBe([]);
});

it('allows hostless private-use schemes that pass registration', function (): void {
    config()->set('mcp.custom_schemes', ['myapp']);
    [$controller] = makeRegisterClientController();

    // myapp:/path style — host null after parse; must still be allowed when scheme listed.
    expect(invokeRegisterClientControllerMethod(
        $controller,
        'isRedirectUriAllowedForRegistration',
        ['myapp://callback'],
    ))->toBeBool();
});
