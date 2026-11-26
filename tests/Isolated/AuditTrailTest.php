<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Actions\BlockClientAction;
use Qiick\McpOAuth\Actions\BlockRedirectHostAction;
use Qiick\McpOAuth\Actions\RevokeConnectedAppAction;
use Qiick\McpOAuth\Actions\SwitchMcpOAuthAction;
use Qiick\McpOAuth\Actions\UnblockRedirectHostAction;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Events\McpClientBlocked;
use Qiick\McpOAuth\Events\McpConsentApproved;
use Qiick\McpOAuth\Events\McpConsentDenied;
use Qiick\McpOAuth\Events\McpGrantRevoked;
use Qiick\McpOAuth\Events\McpOAuthEnabled;
use Qiick\McpOAuth\Events\McpRedirectHostBlocked;
use Qiick\McpOAuth\Events\McpRedirectHostUnblocked;
use Qiick\McpOAuth\Events\McpTokenRevoked;
use Qiick\McpOAuth\Internal\NullAuditLogger;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Testing\FakeAuditLogger;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\TestUser;

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
        ['event' => 'oauth_grant_revoked', 'causer' => (string) $user->getKey(), 'grantId' => $grant->id, 'properties' => ['client_id' => (string) $client->getKey(), 'redirect_host' => null, 'reason' => 'user']],
    ]);
});

it('writes to a no-op logger when the product binds none', function (): void {
    app()->forgetInstance(AuditLogger::class);

    app(SwitchMcpOAuthAction::class)->execute(false, null, static fn (): null => null);

    expect(app(AuditLogger::class))->toBeInstanceOf(NullAuditLogger::class);
});

// --- Failure semantics (Codex review of #60) --------------------------------------

/**
 * A product sink that fails while it is down, as a full disk or a lost
 * connection would, and records into `$recorded` once it is back. The router
 * keeps its controllers between requests in a test, so the same sink must
 * serve the retry.
 */
function throwingAuditLogger(FakeAuditLogger $recorded = new FakeAuditLogger): AuditLogger
{
    return new class($recorded) implements AuditLogger
    {
        public bool $isDown = true;

        public function __construct(public readonly FakeAuditLogger $recorded) {}

        public function record(string $event, ?Authenticatable $causer, ?string $grantId, array $properties): void
        {
            if ($this->isDown) {
                throw new RuntimeException('The audit sink is down.');
            }

            $this->recorded->record($event, $causer, $grantId, $properties);
        }
    };
}

/**
 * A refresh token and the grant it is bound to, for the RFC 7009 path.
 *
 * @return array{refresh_token: string, user_id: string}
 */
function auditedTokensFor(AuthorizeFlowTestCase $testCase, Client $client): array
{
    ['code' => $code, 'user' => $user] = $testCase->obtainAuthorizationCode($client);
    $response = $testCase->withHeaders(['Accept' => 'application/json'])
        ->post('/oauth/token', $testCase->codeExchange($client, $code))
        ->assertOk();

    return ['refresh_token' => (string) $response->json('refresh_token'), 'user_id' => (string) $user->getKey()];
}

it('leaves the switch unwritten and silent when the audit sink fails', function (): void {
    Event::fake([McpOAuthEnabled::class]);
    app()->instance(AuditLogger::class, throwingAuditLogger());
    $writes = new ArrayObject;

    expect(fn () => app(SwitchMcpOAuthAction::class)->execute(true, null, static function (bool $isEnabled) use ($writes): void {
        $writes->append($isEnabled);
    }))->toThrow(RuntimeException::class, 'The audit sink is down.');

    expect($writes->getArrayCopy())->toBe([]);
    Event::assertNotDispatched(McpOAuthEnabled::class);
});

it('keeps a host blocked when the audit of its unblock fails, so the unblock can be retried', function (): void {
    Event::fake([McpRedirectHostUnblocked::class]);
    $admin = $this->createUser();
    $blockedHost = app(BlockRedirectHostAction::class)->execute('evil.example', $admin, isSubdomainMatched: false);
    $auditLogger = throwingAuditLogger($this->auditLogger);
    app()->instance(AuditLogger::class, $auditLogger);

    expect(fn () => app(UnblockRedirectHostAction::class)->execute($blockedHost, $admin))->toThrow(RuntimeException::class);

    expect(OAuthBlockedRedirectHost::query()->whereKey($blockedHost->getKey())->exists())->toBeTrue();
    Event::assertNotDispatched(McpRedirectHostUnblocked::class);

    $auditLogger->isDown = false;
    app(UnblockRedirectHostAction::class)->execute(OAuthBlockedRedirectHost::query()->findOrFail($blockedHost->getKey()), $admin);

    expect(OAuthBlockedRedirectHost::query()->count())->toBe(0)
        ->and(array_column($this->auditLogger->entries, 'event'))->toBe(['oauth_redirect_host_blocked', 'oauth_redirect_host_unblocked']);
});

it('writes no denial evidence when its audit fails, and exactly one on the retry', function (): void {
    Event::fake([McpConsentDenied::class]);
    $client = $this->createClient();
    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();
    $auditLogger = throwingAuditLogger();
    app()->instance(AuditLogger::class, $auditLogger);

    $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')])->assertServerError();

    expect(OAuthConsentRecord::query()->count())->toBe(0);
    Event::assertNotDispatched(McpConsentDenied::class);

    $auditLogger->isDown = false;
    $this->delete('/oauth/authorize', ['auth_token' => $page->json('props.authToken')])->assertRedirect();

    expect(OAuthConsentRecord::query()->where('decision', 'denied')->count())->toBe(1);
});

it('records no approval when its audit fails', function (): void {
    Event::fake([McpConsentApproved::class]);
    $client = $this->createClient();
    $page = $this->actingAs($this->createUser())->get($this->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();
    app()->instance(AuditLogger::class, throwingAuditLogger());

    $this->post('/oauth/authorize', ['auth_token' => $page->json('props.authToken'), 'scopes' => ['mcp:read'], 'role' => 'editor', 'resources' => ['news']])
        ->assertServerError();

    expect(OAuthConsentRecord::query()->count())->toBe(0)
        ->and(OAuthClientMetadata::query()->where('client_id', $client->getKey())->value('first_authorized_at'))->toBeNull();
    Event::assertNotDispatched(McpConsentApproved::class);
});

it('blocks nothing when the audit of a client or host block fails', function (): void {
    Event::fake([McpClientBlocked::class, McpRedirectHostBlocked::class]);
    $admin = $this->createUser();
    $client = $this->createClient();
    app()->instance(AuditLogger::class, throwingAuditLogger());

    expect(fn () => app(BlockClientAction::class)->execute($client, $admin))->toThrow(RuntimeException::class)
        ->and(fn () => app(BlockRedirectHostAction::class)->execute('evil.example', $admin, isSubdomainMatched: false))->toThrow(RuntimeException::class);

    expect($client->fresh()?->getAttribute('revoked'))->toBeFalse()
        ->and(OAuthBlockedRedirectHost::query()->count())->toBe(0);
    Event::assertNotDispatched(McpClientBlocked::class);
    Event::assertNotDispatched(McpRedirectHostBlocked::class);
});

it('revokes no token when the audit of a Connected apps or RFC 7009 revoke fails', function (): void {
    Event::fake([McpGrantRevoked::class, McpTokenRevoked::class]);
    $client = $this->createClient();
    ['refresh_token' => $refreshToken, 'user_id' => $userIdentifier] = auditedTokensFor($this, $client);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), $userIdentifier);
    app()->instance(AuditLogger::class, throwingAuditLogger());

    // RFC 7009 first: the in-memory FakeGrantStore has no transaction to roll back.
    $this->withHeaders(['Accept' => 'application/json'])
        ->post('/oauth/revoke', ['token' => $refreshToken, 'client_id' => (string) $client->getKey()])
        ->assertServerError();
    expect(fn () => app(RevokeConnectedAppAction::class)->execute($grant, TestUser::query()->findOrFail($userIdentifier)))->toThrow(RuntimeException::class);

    expect(Passport::token()->newQuery()->where('revoked', true)->count())->toBe(0)
        ->and(Passport::refreshToken()->newQuery()->count())->toBe(1);
    Event::assertNotDispatched(McpGrantRevoked::class);
    Event::assertNotDispatched(McpTokenRevoked::class);
});

// --- Mapping to the 1.5 activity log (standards review §5, S78) ----------------

it('names the redirect host the grant was approved for on every grant revoke (S78)', function (): void {
    $client = $this->createClient();
    ['refresh_token' => $refreshToken, 'user_id' => $userIdentifier] = auditedTokensFor($this, $client);
    $grant = $this->grantStore()->activeFor((string) $client->getKey(), $userIdentifier);

    $this->withHeaders(['Accept' => 'application/json'])
        ->post('/oauth/revoke', ['token' => $refreshToken, 'client_id' => (string) $client->getKey()])
        ->assertOk();

    expect(array_slice($this->auditLogger->entries, 1))->toBe([
        ['event' => 'oauth_grant_revoked', 'causer' => null, 'grantId' => $grant?->id, 'properties' => [
            'client_id' => (string) $client->getKey(),
            'redirect_host' => 'app.example',
            'reason' => 'client',
        ]],
    ]);
});

it('records nothing for an RFC 7009 revoke of an access token, which leaves the grant in place', function (): void {
    $client = $this->createClient();
    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $accessToken = (string) $this->withHeaders(['Accept' => 'application/json'])
        ->post('/oauth/token', $this->codeExchange($client, $code))
        ->json('access_token');

    $this->withHeaders(['Accept' => 'application/json'])
        ->post('/oauth/revoke', ['token' => $accessToken, 'client_id' => (string) $client->getKey()])
        ->assertOk();

    expect(array_column($this->auditLogger->entries, 'event'))->toBe(['oauth_consent_approved']);
});
