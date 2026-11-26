<?php

declare(strict_types=1);

use Illuminate\Support\Str;
use Qiick\McpOAuth\Actions\BlockClientAction;
use Qiick\McpOAuth\Actions\BlockRedirectHostAction;
use Qiick\McpOAuth\Actions\RevokeConnectedAppAction;
use Qiick\McpOAuth\Actions\SwitchMcpOAuthAction;
use Qiick\McpOAuth\Actions\UnblockRedirectHostAction;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Internal\NullAuditLogger;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Testing\FakeAuditLogger;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * The package writes audit entries through the product's AuditLogger
 * (design §3.1, §4.3, §8.2, S78): ids and hosts only, never token material.
 */
beforeEach(function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $this->auditLogger = new FakeAuditLogger;
    app()->instance(AuditLogger::class, $this->auditLogger);
});

it('records a consent approval and a denial, naming the client and its redirect host (S78)', function (): void {
    $client = $this->createClient();
    ['user' => $user] = $this->obtainAuthorizationCode($client);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), (string) $user->getKey());

    $page = $this->actingAs($user)->get($this->authorizeUrl($client), ['X-Inertia' => 'true']);
    $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')]);

    expect($this->auditLogger->entries)->toBe([
        ['event' => 'oauth_consent_approved', 'causer' => (string) $user->getKey(), 'grantId' => $grant?->id, 'properties' => [
            'client_id' => (string) $client->getKey(),
            'redirect_host' => 'app.example',
            'scopes' => ['mcp:read'],
            'resources' => ['news'],
        ]],
        ['event' => 'oauth_consent_denied', 'causer' => (string) $user->getKey(), 'grantId' => null, 'properties' => [
            'client_id' => (string) $client->getKey(),
            'redirect_host' => 'app.example',
        ]],
    ]);
});

it('records switching OAuth on and off', function (): void {
    $admin = $this->createUser();

    app(SwitchMcpOAuthAction::class)->execute(true, $admin, static fn (): null => null);
    app(SwitchMcpOAuthAction::class)->execute(false, null, static fn (): null => null);

    expect($this->auditLogger->entries)->toBe([
        ['event' => 'mcp_oauth_enabled', 'causer' => (string) $admin->getKey(), 'grantId' => null, 'properties' => []],
        ['event' => 'mcp_oauth_disabled', 'causer' => null, 'grantId' => null, 'properties' => []],
    ]);
});

it('records a client block, a host block and an unblock', function (): void {
    $admin = $this->createUser();
    $client = $this->createClient(['https://other.example/callback']);

    app(BlockClientAction::class)->execute($client, $admin);
    $blockedHost = app(BlockRedirectHostAction::class)->execute('evil.example', $admin, isSubdomainMatched: false);
    app(UnblockRedirectHostAction::class)->execute($blockedHost, $admin);

    expect($this->auditLogger->entries)->toBe([
        ['event' => 'oauth_client_blocked', 'causer' => (string) $admin->getKey(), 'grantId' => null, 'properties' => ['client_id' => (string) $client->getKey()]],
        ['event' => 'oauth_redirect_host_blocked', 'causer' => (string) $admin->getKey(), 'grantId' => null, 'properties' => ['host' => 'evil.example', 'match_mode' => 'exact']],
        ['event' => 'oauth_redirect_host_unblocked', 'causer' => (string) $admin->getKey(), 'grantId' => null, 'properties' => ['host' => 'evil.example']],
    ]);
});

it('records a revoke from Connected apps', function (): void {
    $user = $this->createUser();
    $client = $this->createClient();
    $grant = new GrantRecord((string) Str::uuid7(), (string) $client->getKey(), (string) $user->getKey(), false, ['mcp:read'], new DateTimeImmutable, null);
    $this->grantStore()->seed($grant);

    app(RevokeConnectedAppAction::class)->execute($grant, $user);

    expect($this->auditLogger->entries)->toBe([
        ['event' => 'oauth_grant_revoked', 'causer' => (string) $user->getKey(), 'grantId' => $grant->id, 'properties' => ['client_id' => (string) $client->getKey(), 'reason' => 'user']],
    ]);
});

it('writes to a no-op logger when the product binds none', function (): void {
    app()->forgetInstance(AuditLogger::class);

    app(SwitchMcpOAuthAction::class)->execute(false, null, static fn (): null => null);

    expect(app(AuditLogger::class))->toBeInstanceOf(NullAuditLogger::class);
});
