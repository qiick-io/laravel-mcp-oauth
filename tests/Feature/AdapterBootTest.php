<?php

declare(strict_types=1);

use Qiick\McpOAuth\Contracts\ApiKeyDoor;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\ConsentView;
use Qiick\McpOAuth\Contracts\GrantAuthorizer;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Contracts\McpCredentialBinder;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;
use Qiick\McpOAuth\McpOAuthServiceProvider;
use Qiick\McpOAuth\Testing\FakeApiKeyDoor;
use Qiick\McpOAuth\Testing\FakeConsentProvider;
use Qiick\McpOAuth\Testing\FakeGrantAuthorizer;
use Qiick\McpOAuth\Testing\FakeGrantStore;
use Qiick\McpOAuth\Testing\FakeMcpCredentialBinder;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Views\InertiaConsentView;

/**
 * S81 / design §5.6: with `mcp-oauth.enabled` on, boot fails closed when an
 * adapter the OAuth endpoints need is not bound; with it off, a product may
 * install the package before writing its adapters.
 */
function bindEveryAdapter(): void
{
    app()->instance(ConsentProvider::class, new FakeConsentProvider(AuthorizeFlowTestCase::defaultConsentOptions()));
    app()->bind(ConsentView::class, InertiaConsentView::class);
    app()->singleton(GrantStore::class, FakeGrantStore::class);
    app()->instance(GrantAuthorizer::class, new FakeGrantAuthorizer);
    app()->instance(ApiKeyDoor::class, new FakeApiKeyDoor);
    app()->instance(McpCredentialBinder::class, new FakeMcpCredentialBinder);
}

it('boots without adapters while OAuth is off', function (): void {
    config()->set('mcp-oauth.enabled', false);
    app()->offsetUnset(ConsentView::class);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())->not->toThrow(Exception::class);
});

it('boots with OAuth on once every adapter is bound', function (): void {
    config()->set('mcp-oauth.enabled', true);
    bindEveryAdapter();

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())->not->toThrow(Exception::class);
});

it('fails boot with OAuth on and an adapter missing, naming it', function (string $contract): void {
    config()->set('mcp-oauth.enabled', true);
    bindEveryAdapter();
    app()->offsetUnset($contract);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, $contract);
})->with([
    ConsentView::class,
    ConsentProvider::class,
    GrantStore::class,
    GrantAuthorizer::class,
    ApiKeyDoor::class,
    McpCredentialBinder::class,
]);

it('tells a product without Inertia how to get a consent page', function (): void {
    config()->set('mcp-oauth.enabled', true);
    bindEveryAdapter();
    app()->offsetUnset(ConsentView::class);

    expect(fn () => (new McpOAuthServiceProvider($this->app))->boot())
        ->toThrow(InvalidMcpOAuthConfigException::class, 'inertiajs/inertia-laravel');
});
