<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Events\McpPassportKeysFoundMissingEvent;
use Qiick\McpOAuth\Http\Middleware\EnsureMcpOAuthEnabledMiddleware;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Testing\FakeAdminSwitch;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

function middlewareServer(): McpOAuthServer
{
    app()->forgetInstance(McpOAuthServer::class);

    return app(McpOAuthServer::class);
}

it('aborts 404 when OAuth is off', function (): void {
    config()->set('mcp-oauth.enabled', false);
    app()->instance(AdminSwitch::class, new FakeAdminSwitch(isEnabled: false));

    $middleware = new EnsureMcpOAuthEnabledMiddleware(middlewareServer());

    expect(fn () => $middleware->handle(Request::create('/oauth/register', 'POST'), fn () => response('ok')))
        ->toThrow(NotFoundHttpException::class);
});

it('answers 503 with both wire keys when Passport keys are missing', function (): void {
    Event::fake([McpPassportKeysFoundMissingEvent::class]);

    config()->set('mcp-oauth.enabled', true);
    config()->set('mcp-oauth.mcp_enabled', true);
    config()->set('passport.private_key', '');
    config()->set('passport.public_key', '');
    app()->instance(AdminSwitch::class, new FakeAdminSwitch(isEnabled: true));

    $missingKeyDirectory = sys_get_temp_dir().'/mcp-oauth-mw-keys-'.uniqid('', true);
    mkdir($missingKeyDirectory, 0700);
    Passport::loadKeysFrom($missingKeyDirectory);

    $middleware = new EnsureMcpOAuthEnabledMiddleware(middlewareServer());
    $response = $middleware->handle(Request::create('/oauth/register', 'POST'), fn () => response('ok'));

    expect($response->getStatusCode())->toBe(503)
        ->and($response->getData(true))->toBe([
            'error' => 'temporarily_unavailable',
            'error_description' => 'OAuth is unavailable because Passport keys are missing.',
        ]);

    Event::assertDispatched(McpPassportKeysFoundMissingEvent::class, function (McpPassportKeysFoundMissingEvent $event): bool {
        return $event->endpoint === 'oauth/register' && $event->reason === 'unreadable';
    });
});

it('passes through when OAuth is on and keys are present', function (): void {
    $privateKey = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    openssl_pkey_export($privateKey, $privatePem);
    $details = openssl_pkey_get_details($privateKey);

    config()->set('mcp-oauth.enabled', true);
    config()->set('mcp-oauth.mcp_enabled', true);
    config()->set('passport.private_key', $privatePem);
    config()->set('passport.public_key', $details['key']);
    app()->instance(AdminSwitch::class, new FakeAdminSwitch(isEnabled: true));

    $middleware = new EnsureMcpOAuthEnabledMiddleware(middlewareServer());
    $response = $middleware->handle(
        Request::create('/oauth/register', 'POST'),
        fn () => response('next-ok', 200),
    );

    expect($response->getContent())->toBe('next-ok')
        ->and($response->getStatusCode())->toBe(200);
});
