<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Actions\RevokeConnectedAppAction;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpGrantRevoked;
use Qiick\McpOAuth\McpOAuthSettingsRoutes;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\HookedGrantStore;
use Qiick\McpOAuth\Tests\Support\TestUser;

uses(AuthorizeFlowTestCase::class);

/**
 * Connected apps (design §4.2, §5.2): a signed-in user lists the MCP clients
 * they authorised and revokes one. The routes stay up while OAuth is off, so
 * leftover grants can still be revoked.
 */

/**
 * A grant of `$user` for a new client, with an access token and its refresh
 * token bound to it.
 *
 * @return array{grant: GrantRecord, client: Client, accessTokenId: string}
 */
function connectedApp(AuthorizeFlowTestCase $testCase, TestUser $user, string $clientName = 'Cursor'): array
{
    $client = $testCase->createClient(['https://app.example/callback', 'https://app.example/second']);
    $client->forceFill(['name' => $clientName])->save();
    $grant = new GrantRecord((string) Str::uuid7(), (string) $client->getKey(), (string) $user->getKey(), false, ['mcp:read'], new DateTimeImmutable('2026-11-20 10:00:00'), null, ['role' => 'editor']);
    $testCase->grantStore()->seed($grant);
    $accessTokenId = Str::random(80);

    DB::table('oauth_access_tokens')->insert([
        'id' => $accessTokenId, 'user_id' => $user->getKey(), 'client_id' => $client->getKey(), 'scopes' => '["mcp:use"]',
        'revoked' => false, 'expires_at' => now()->addHour(), 'api_key_id' => $grant->id, 'created_at' => now(), 'updated_at' => now(),
    ]);
    DB::table('oauth_refresh_tokens')->insert(['id' => Str::random(80), 'access_token_id' => $accessTokenId, 'revoked' => false, 'expires_at' => now()->addDays(30)]);

    return ['grant' => $grant, 'client' => $client, 'accessTokenId' => $accessTokenId];
}

beforeEach(function (): void {
    Route::middleware(['web', 'auth'])->group(static fn () => McpOAuthSettingsRoutes::register());
});

it('lists the signed-in user\'s own active grants, with OAuth off too', function (bool $isOAuthEnabled): void {
    if ($isOAuthEnabled) {
        $this->enableOAuth();
    }

    $user = $this->createUser();
    ['grant' => $grant, 'client' => $client] = connectedApp($this, $user);
    connectedApp($this, $this->createUser(), 'Someone else\'s app');
    ['grant' => $revokedGrant] = connectedApp($this, $user, 'Revoked app');
    $this->grantStore()->revoke($revokedGrant->id, null, RevocationReason::User);

    $response = $this->actingAs($user)->getJson('/settings/connected-apps')->assertOk();

    expect($response->json('connectedApps'))->toBe([[
        'id' => $grant->id,
        'client' => ['id' => (string) $client->getKey(), 'name' => 'Cursor', 'redirectHosts' => ['app.example']],
        'scopes' => ['mcp:read'],
        'display' => ['role' => 'editor'],
        'authorizedAt' => '2026-11-20T10:00:00+00:00',
        'lastUsedAt' => null,
    ]]);
})->with([
    'OAuth on' => [true],
    'OAuth off' => [false],
]);

it('needs a signed-in user', function (): void {
    $this->getJson('/settings/connected-apps')->assertUnauthorized();
});

it('revokes a grant and every token bound to it, then tells the product', function (): void {
    Event::fake([McpGrantRevoked::class]);
    $user = $this->createUser();
    ['grant' => $grant, 'client' => $client, 'accessTokenId' => $accessTokenId] = connectedApp($this, $user);
    ['accessTokenId' => $otherAccessTokenId] = connectedApp($this, $user, 'Another app');

    $this->actingAs($user)->deleteJson("/settings/connected-apps/{$grant->id}")->assertNoContent();

    expect($this->grantStore()->find($grant->id)?->revoked)->toBeTrue()
        ->and(collect($this->grantStore()->revocations)->firstWhere('grantId', $grant->id))->toBe([
            'grantId' => $grant->id,
            'actorIdentifier' => (string) $user->getKey(),
            'reason' => RevocationReason::User,
        ])
        ->and(DB::table('oauth_access_tokens')->where('id', $accessTokenId)->value('revoked'))->toBeTruthy()
        ->and(DB::table('oauth_refresh_tokens')->where('access_token_id', $accessTokenId)->value('revoked'))->toBeTruthy()
        ->and(DB::table('oauth_access_tokens')->where('id', $otherAccessTokenId)->value('revoked'))->toBeFalsy();

    Event::assertDispatched(McpGrantRevoked::class, static fn (McpGrantRevoked $event): bool => $event->grantId === $grant->id
        && $event->clientId === (string) $client->getKey()
        && $event->userIdentifier === (string) $user->getKey()
        && $event->actorIdentifier === (string) $user->getKey()
        && $event->reason === RevocationReason::User);
});

it('answers 404 for a grant that is not the user\'s own active one', function (string $whose): void {
    Event::fake([McpGrantRevoked::class]);
    $user = $this->createUser();
    ['grant' => $grant] = connectedApp($this, $whose === 'another user' ? $this->createUser() : $user);

    if ($whose === 'already revoked') {
        $this->grantStore()->revoke($grant->id, null, RevocationReason::User);
    }

    $grantId = $whose === 'unknown' ? (string) Str::uuid7() : $grant->id;

    $this->actingAs($user)->deleteJson("/settings/connected-apps/{$grantId}")->assertNotFound();

    Event::assertNotDispatched(McpGrantRevoked::class);
})->with(['another user', 'already revoked', 'unknown']);

it('redirects back after a form or Inertia post', function (): void {
    $user = $this->createUser();
    ['grant' => $grant] = connectedApp($this, $user);

    $this->actingAs($user)->from('/settings/connected-apps-page')
        ->delete("/settings/connected-apps/{$grant->id}")
        ->assertRedirect('/settings/connected-apps-page');
});

it('lists a grant whose client is gone, or that has no dates, so it can still be revoked', function (): void {
    $user = $this->createUser();
    $client = $this->createClient(['https://app.example/callback', 'https://app.example/second', 'https://other.example/callback']);
    $grant = new GrantRecord((string) Str::uuid7(), (string) $client->getKey(), (string) $user->getKey(), false, ['mcp:read'], null, null);
    $orphanGrant = new GrantRecord((string) Str::uuid7(), (string) Str::uuid7(), (string) $user->getKey(), false, ['mcp:read'], null, null);
    $this->grantStore()->seed($grant);
    $this->grantStore()->seed($orphanGrant);

    $connectedApps = collect($this->actingAs($user)->getJson('/settings/connected-apps')->assertOk()->json('connectedApps'))->keyBy('id');

    expect($connectedApps[$grant->id]['client']['redirectHosts'])->toBe(['app.example', 'other.example'])
        ->and($connectedApps[$grant->id]['authorizedAt'])->toBeNull()
        ->and($connectedApps[$orphanGrant->id]['client'])->toBe(['id' => $orphanGrant->clientId, 'name' => null, 'redirectHosts' => []]);
});

it('revokes the user\'s unexchanged codes for that client too (S76)', function (): void {
    $user = $this->createUser();
    ['grant' => $grant, 'client' => $client] = connectedApp($this, $user);
    $authCode = static fn (string $userIdentifier): string => tap(Str::random(80), static fn (string $codeId) => DB::table('oauth_auth_codes')->insert([
        'id' => $codeId, 'user_id' => $userIdentifier, 'client_id' => $client->getKey(), 'scopes' => '["mcp:use"]', 'revoked' => false, 'expires_at' => now()->addMinutes(5),
    ]));
    $userCode = $authCode((string) $user->getKey());
    $otherUserCode = $authCode((string) $this->createUser()->getKey());

    $this->actingAs($user)->deleteJson("/settings/connected-apps/{$grant->id}")->assertNoContent();

    expect(DB::table('oauth_auth_codes')->where('id', $userCode)->value('revoked'))->toBeTruthy()
        ->and(DB::table('oauth_auth_codes')->where('id', $otherUserCode)->value('revoked'))->toBeFalsy();
});

/**
 * An auth code of `$userIdentifier` for `$client`, expiring `$expiresInMinutes`
 * from now (Passport writes the issue time plus the code TTL).
 */
function unexchangedCode(Client $client, string $userIdentifier, int $expiresInMinutes = 5): string
{
    return tap(Str::random(80), static fn (string $codeId) => DB::table('oauth_auth_codes')->insert([
        'id' => $codeId, 'user_id' => $userIdentifier, 'client_id' => $client->getKey(), 'scopes' => '["mcp:use"]',
        'revoked' => false, 'expires_at' => now()->addMinutes($expiresInMinutes),
    ]));
}

it('leaves the code of a newer consent alone when an older grant is revoked (#49 review)', function (): void {
    $user = $this->createUser();
    ['grant' => $olderGrant, 'client' => $client] = connectedApp($this, $user);
    // The user approved again meanwhile: a newer active grant, and its fresh code.
    $this->grantStore()->seed(new GrantRecord((string) Str::uuid7(), (string) $client->getKey(), (string) $user->getKey(), false, ['mcp:read'], new DateTimeImmutable, null));
    $newerCode = unexchangedCode($client, (string) $user->getKey(), 10);

    app(RevokeConnectedAppAction::class)->execute($olderGrant, $user);

    expect(DB::table('oauth_auth_codes')->where('id', $newerCode)->value('revoked'))->toBeFalsy();
});

it('leaves a code issued while the revoke runs alone (#49 review)', function (): void {
    $user = $this->createUser();
    ['grant' => $grant, 'client' => $client] = connectedApp($this, $user);
    $olderCode = unexchangedCode($client, (string) $user->getKey());
    $hookedGrantStore = new HookedGrantStore($this->grantStore());
    app()->instance(GrantStore::class, $hookedGrantStore);
    $codeIssuedDuringTheRevoke = null;
    // Two seconds into the revoke, a new approval's code lands with the full TTL.
    $hookedGrantStore->beforeRevoke = function () use ($client, $user, &$codeIssuedDuringTheRevoke): void {
        $this->travel(2)->seconds();
        $codeIssuedDuringTheRevoke = unexchangedCode($client, (string) $user->getKey(), 10);
    };

    app(RevokeConnectedAppAction::class)->execute($grant, $user);

    expect(DB::table('oauth_auth_codes')->where('id', $olderCode)->value('revoked'))->toBeTruthy()
        ->and(DB::table('oauth_auth_codes')->where('id', $codeIssuedDuringTheRevoke)->value('revoked'))->toBeFalsy();
});

it('rolls the whole revoke back, and tells no one, when a step fails (Devin review of #49)', function (): void {
    Event::fake([McpGrantRevoked::class]);
    $user = $this->createUser();
    ['grant' => $grant, 'accessTokenId' => $accessTokenId] = connectedApp($this, $user);
    $hookedGrantStore = new HookedGrantStore($this->grantStore());
    app()->instance(GrantStore::class, $hookedGrantStore);
    // The step after the token revocation fails (a deadlock, a dropped connection).
    $hookedGrantStore->afterNextActiveFor = static function (): never {
        throw new RuntimeException('The database went away.');
    };

    expect(fn () => app(RevokeConnectedAppAction::class)->execute($grant, $user))->toThrow(RuntimeException::class);

    expect(DB::table('oauth_access_tokens')->where('id', $accessTokenId)->value('revoked'))->toBeFalsy()
        ->and(DB::table('oauth_refresh_tokens')->where('access_token_id', $accessTokenId)->value('revoked'))->toBeFalsy();
    Event::assertNotDispatched(McpGrantRevoked::class);
});
