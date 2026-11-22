<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Bridge\FamilyRevokingRefreshTokenRepository;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpRefreshTokenReused;
use Qiick\McpOAuth\Testing\FakeGrantStore;
use Qiick\McpOAuth\Tests\Support\PassportBootedTestCase;

uses(PassportBootedTestCase::class);

beforeEach(function (): void {
    Schema::dropIfExists('oauth_refresh_tokens');
    Schema::dropIfExists('oauth_access_tokens');

    Schema::create('oauth_access_tokens', function (Blueprint $table): void {
        $table->char('id', 80)->primary();
        $table->foreignId('user_id')->nullable()->index();
        $table->uuid('client_id');
        $table->string('name')->nullable();
        $table->text('scopes')->nullable();
        $table->boolean('revoked');
        $table->string('api_key_id')->nullable()->index();
        $table->timestamps();
        $table->dateTime('expires_at')->nullable();
    });

    Schema::create('oauth_refresh_tokens', function (Blueprint $table): void {
        $table->char('id', 80)->primary();
        $table->char('access_token_id', 80)->index();
        $table->boolean('revoked');
        $table->dateTime('expires_at')->nullable();
    });
});

/**
 * @return array{grant: GrantRecord, accessTokenId: string, refreshTokenId: string, siblingAccessTokenId: string, siblingRefreshTokenId: string}
 */
function seedBoundFamily(FakeGrantStore $grantStore, string $grantId = 'grant-uuid-1'): array
{
    $grant = new GrantRecord(
        id: $grantId,
        clientId: '11111111-1111-1111-1111-111111111111',
        userIdentifier: '42',
        revoked: false,
        scopes: ['mcp:use'],
        authorizedAt: new DateTimeImmutable,
        lastUsedAt: null,
    );
    $grantStore->seed($grant);

    $accessTokenId = 'access-token-primary';
    $refreshTokenId = 'refresh-token-primary';
    $siblingAccessTokenId = 'access-token-sibling';
    $siblingRefreshTokenId = 'refresh-token-sibling';

    Passport::token()->forceFill([
        'id' => $accessTokenId,
        'user_id' => 42,
        'client_id' => $grant->clientId,
        'scopes' => ['mcp:use'],
        'revoked' => false,
        'api_key_id' => $grantId,
        'expires_at' => now()->addHour(),
    ])->save();

    Passport::token()->forceFill([
        'id' => $siblingAccessTokenId,
        'user_id' => 42,
        'client_id' => $grant->clientId,
        'scopes' => ['mcp:use'],
        'revoked' => false,
        'api_key_id' => $grantId,
        'expires_at' => now()->addHour(),
    ])->save();

    Passport::refreshToken()->forceFill([
        'id' => $refreshTokenId,
        'access_token_id' => $accessTokenId,
        'revoked' => false,
        'expires_at' => now()->addDay(),
    ])->save();

    Passport::refreshToken()->forceFill([
        'id' => $siblingRefreshTokenId,
        'access_token_id' => $siblingAccessTokenId,
        'revoked' => false,
        'expires_at' => now()->addDay(),
    ])->save();

    return [
        'grant' => $grant,
        'accessTokenId' => $accessTokenId,
        'refreshTokenId' => $refreshTokenId,
        'siblingAccessTokenId' => $siblingAccessTokenId,
        'siblingRefreshTokenId' => $siblingRefreshTokenId,
    ];
}

it('binds Passport RefreshTokenRepository to the family-revoking implementation', function (): void {
    expect(app(PassportRefreshTokenRepository::class))
        ->toBeInstanceOf(FamilyRevokingRefreshTokenRepository::class);
});

it('marks a live refresh token revoked without touching the family on first revoke', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    $repository->revokeRefreshToken($family['refreshTokenId']);

    expect(Passport::refreshToken()->newQuery()->whereKey($family['refreshTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->whereKey($family['siblingRefreshTokenId'])->value('revoked'))->toBeFalse()
        ->and(Passport::token()->newQuery()->whereKey($family['accessTokenId'])->value('revoked'))->toBeFalse()
        ->and($grantStore->find($family['grant']->id)?->revoked)->toBeFalse()
        ->and($grantStore->revocations)->toBe([]);
});

it('revokes the token family and grant when a used refresh token is presented again', function (): void {
    Event::fake([McpRefreshTokenReused::class]);

    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    $repository->revokeRefreshToken($family['refreshTokenId']);
    $repository->revokeRefreshToken($family['refreshTokenId']);

    expect(Passport::token()->newQuery()->whereKey($family['accessTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::token()->newQuery()->whereKey($family['siblingAccessTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->whereKey($family['refreshTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->whereKey($family['siblingRefreshTokenId'])->value('revoked'))->toBeTrue()
        ->and($grantStore->find($family['grant']->id)?->revoked)->toBeTrue()
        ->and($grantStore->revocations)->toHaveCount(1)
        ->and($grantStore->revocations[0]['reason'])->toBe(RevocationReason::Reuse);

    Event::assertDispatched(McpRefreshTokenReused::class, function (McpRefreshTokenReused $event) use ($family): bool {
        return $event->grantId === $family['grant']->id
            && $event->clientId === $family['grant']->clientId
            && $event->userIdentifier === '42'
            && $event->revokedTokenCount >= 1;
    });
});

it('revokes the family when isRefreshTokenRevoked sees an already-revoked refresh token', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    Passport::refreshToken()->newQuery()->whereKey($family['refreshTokenId'])->update(['revoked' => true]);

    expect($repository->isRefreshTokenRevoked($family['refreshTokenId']))->toBeTrue()
        ->and(Passport::token()->newQuery()->whereKey($family['siblingAccessTokenId'])->value('revoked'))->toBeTrue()
        ->and($grantStore->find($family['grant']->id)?->revoked)->toBeTrue();
});

it('S59: refuses a refresh token whose access token has no active bound grant', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    $grantStore->revoke($family['grant']->id, null, RevocationReason::User);

    expect($repository->isRefreshTokenRevoked($family['refreshTokenId']))->toBeTrue()
        ->and(Passport::token()->newQuery()->whereKey($family['accessTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->whereKey($family['siblingRefreshTokenId'])->value('revoked'))->toBeTrue();
});

it('does not revoke a newer grant when reuse hits a family bound to an older grant', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $oldFamily = seedBoundFamily($grantStore, 'grant-old');
    $newGrant = new GrantRecord(
        id: 'grant-new',
        clientId: $oldFamily['grant']->clientId,
        userIdentifier: '42',
        revoked: false,
        scopes: ['mcp:use'],
        authorizedAt: new DateTimeImmutable,
        lastUsedAt: null,
    );
    $grantStore->seed($newGrant);

    Passport::token()->forceFill([
        'id' => 'access-token-new',
        'user_id' => 42,
        'client_id' => $newGrant->clientId,
        'scopes' => ['mcp:use'],
        'revoked' => false,
        'api_key_id' => $newGrant->id,
        'expires_at' => now()->addHour(),
    ])->save();

    $repository = app(FamilyRevokingRefreshTokenRepository::class);
    $repository->revokeRefreshToken($oldFamily['refreshTokenId']);
    $repository->revokeRefreshToken($oldFamily['refreshTokenId']);

    expect($grantStore->find('grant-old')?->revoked)->toBeTrue()
        ->and($grantStore->find('grant-new')?->revoked)->toBeFalse()
        ->and(Passport::token()->newQuery()->whereKey('access-token-new')->value('revoked'))->toBeFalse();
});

it('revokes the family when two processes race revokeRefreshToken on the same token', function (): void {
    if (! function_exists('pcntl_fork') || ! function_exists('pcntl_waitpid')) {
        expect(function_exists('pcntl_fork'))->toBeTrue('pcntl is required for the parallel race test');

        return;
    }

    $databasePath = tempnam(sys_get_temp_dir(), 'mcp-oauth-race-');
    expect($databasePath)->not->toBeFalse();
    expect(file_exists($databasePath))->toBeTrue();

    // Keep Testbench's default :memory: connection intact; Passport models use
    // this dedicated file DB so forked workers share WAL state (design S57).
    config([
        'passport.connection' => 'sqlite_race',
        'database.connections.sqlite_race' => [
            'driver' => 'sqlite',
            'database' => $databasePath,
            'prefix' => '',
            'foreign_key_constraints' => true,
        ],
    ]);
    DB::purge('sqlite_race');
    DB::reconnect('sqlite_race');
    DB::connection('sqlite_race')->statement('PRAGMA journal_mode=WAL;');
    DB::connection('sqlite_race')->statement('PRAGMA busy_timeout=5000;');

    Schema::connection('sqlite_race')->dropIfExists('oauth_refresh_tokens');
    Schema::connection('sqlite_race')->dropIfExists('oauth_access_tokens');
    Schema::connection('sqlite_race')->create('oauth_access_tokens', function (Blueprint $table): void {
        $table->char('id', 80)->primary();
        $table->foreignId('user_id')->nullable()->index();
        $table->uuid('client_id');
        $table->string('name')->nullable();
        $table->text('scopes')->nullable();
        $table->boolean('revoked');
        $table->string('api_key_id')->nullable()->index();
        $table->timestamps();
        $table->dateTime('expires_at')->nullable();
    });
    Schema::connection('sqlite_race')->create('oauth_refresh_tokens', function (Blueprint $table): void {
        $table->char('id', 80)->primary();
        $table->char('access_token_id', 80)->index();
        $table->boolean('revoked');
        $table->dateTime('expires_at')->nullable();
    });

    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $refreshTokenId = $family['refreshTokenId'];

    $barrierPath = tempnam(sys_get_temp_dir(), 'mcp-oauth-barrier-');
    expect($barrierPath)->not->toBeFalse();
    file_put_contents($barrierPath, '0');

    $childPids = [];

    for ($childIndex = 0; $childIndex < 2; $childIndex++) {
        $childPid = pcntl_fork();

        if ($childPid === -1) {
            throw new RuntimeException('pcntl_fork failed');
        }

        if ($childPid === 0) {
            $barrierHandle = fopen($barrierPath, 'c+');
            flock($barrierHandle, LOCK_EX);
            $readyCount = (int) stream_get_contents($barrierHandle);
            $readyCount++;
            ftruncate($barrierHandle, 0);
            rewind($barrierHandle);
            fwrite($barrierHandle, (string) $readyCount);
            flock($barrierHandle, LOCK_UN);

            while (true) {
                flock($barrierHandle, LOCK_SH);
                rewind($barrierHandle);
                $readyCount = (int) stream_get_contents($barrierHandle);
                flock($barrierHandle, LOCK_UN);

                if ($readyCount >= 2) {
                    break;
                }

                usleep(1_000);
            }

            fclose($barrierHandle);

            DB::purge('sqlite_race');
            DB::reconnect('sqlite_race');
            DB::connection('sqlite_race')->statement('PRAGMA busy_timeout=5000;');

            app(FamilyRevokingRefreshTokenRepository::class)->revokeRefreshToken($refreshTokenId);

            posix_kill(getmypid(), SIGKILL);
            exit(0);
        }

        $childPids[] = $childPid;
    }

    foreach ($childPids as $childPid) {
        pcntl_waitpid($childPid, $status);
    }

    DB::purge('sqlite_race');
    DB::reconnect('sqlite_race');

    // Sibling revoked proves the race loser ran family revoke (design S57).
    // GrantStore is in-memory per process, so grant assertions stay in the
    // sequential reuse test above.
    expect(Passport::refreshToken()->newQuery()->whereKey($refreshTokenId)->value('revoked'))->toBeTrue()
        ->and(Passport::token()->newQuery()->whereKey($family['accessTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::token()->newQuery()->whereKey($family['siblingAccessTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->whereKey($family['siblingRefreshTokenId'])->value('revoked'))->toBeTrue();

    config(['passport.connection' => null]);
    @unlink($barrierPath);
    @unlink($databasePath);
    @unlink($databasePath.'-wal');
    @unlink($databasePath.'-shm');
});
