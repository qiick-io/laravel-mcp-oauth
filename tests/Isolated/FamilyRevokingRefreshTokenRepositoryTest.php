<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
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
        $table->string('id', 80)->primary();
        $table->unsignedBigInteger('user_id')->nullable()->index();
        $table->uuid('client_id');
        $table->string('name')->nullable();
        $table->text('scopes')->nullable();
        $table->boolean('revoked');
        $table->string('api_key_id')->nullable()->index();
        $table->timestamps();
        $table->dateTime('expires_at')->nullable();
    });

    Schema::create('oauth_refresh_tokens', function (Blueprint $table): void {
        $table->string('id', 80)->primary();
        $table->string('access_token_id', 80)->index();
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

/**
 * League-order issuance after revokeRefreshToken returns (AT then RT).
 *
 * @return array{accessTokenId: string, refreshTokenId: string}
 */
function issueTokensAfterRevoke(string $prefix, string $clientId, string $grantId): array
{
    $accessTokenId = $prefix.'-new-at';
    $refreshTokenId = $prefix.'-new-rt';

    Passport::token()->forceFill([
        'id' => $accessTokenId,
        'user_id' => 42,
        'client_id' => $clientId,
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

    return compact('accessTokenId', 'refreshTokenId');
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

it('revokes the token family and throws invalid_grant when a used refresh token is presented again', function (): void {
    Event::fake([McpRefreshTokenReused::class]);

    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    $repository->revokeRefreshToken($family['refreshTokenId']);

    expect(fn () => $repository->revokeRefreshToken($family['refreshTokenId']))
        ->toThrow(OAuthServerException::class);

    expect(Passport::token()->newQuery()->whereKey($family['accessTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::token()->newQuery()->whereKey($family['siblingAccessTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->whereKey($family['refreshTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->whereKey($family['siblingRefreshTokenId'])->value('revoked'))->toBeTrue()
        ->and($grantStore->find($family['grant']->id)?->revoked)->toBeTrue()
        ->and($grantStore->revocations)->toHaveCount(1)
        ->and($grantStore->revocations[0]['reason'])->toBe(RevocationReason::Reuse);

    Event::assertDispatched(McpRefreshTokenReused::class, function (McpRefreshTokenReused $event) use ($family): bool {
        // 2 access + 1 still-live sibling refresh (primary RT already CAS-revoked).
        return $event->grantId === $family['grant']->id
            && $event->clientId === $family['grant']->clientId
            && $event->userIdentifier === '42'
            && $event->revokedTokenCount === 3;
    });
});

it('treats a missing refresh token as revoked without family side effects', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    expect($repository->isRefreshTokenRevoked('missing-refresh-token'))->toBeTrue()
        ->and(Passport::token()->newQuery()->whereKey($family['accessTokenId'])->value('revoked'))->toBeFalse()
        ->and($grantStore->revocations)->toBe([]);
});

it('allows a first revoke when the access token has no grant binding', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    Passport::token()->newQuery()->whereKey($family['accessTokenId'])->update(['api_key_id' => null]);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    $repository->revokeRefreshToken($family['refreshTokenId']);

    expect(Passport::refreshToken()->newQuery()->whereKey($family['refreshTokenId'])->value('revoked'))->toBeTrue()
        ->and($grantStore->find($family['grant']->id)?->revoked)->toBeFalse();
});

it('S59: refuses refresh when the bound access token row is missing', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    Passport::token()->newQuery()->whereKey($family['accessTokenId'])->delete();
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    expect($repository->isRefreshTokenRevoked($family['refreshTokenId']))->toBeTrue();
});

it('revokes refresh tokens pointing at a purged access token without touching the grant', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    Passport::token()->newQuery()->whereKey($family['accessTokenId'])->delete();
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    $repository->revokeFamilyForRefreshToken($family['refreshTokenId']);

    expect(Passport::refreshToken()->newQuery()->whereKey($family['refreshTokenId'])->value('revoked'))->toBeTrue()
        ->and(Passport::token()->newQuery()->whereKey($family['siblingAccessTokenId'])->value('revoked'))->toBeFalse()
        ->and($grantStore->find($family['grant']->id)?->revoked)->toBeFalse();
});

it('is a no-op when revokeFamily is called for an unknown refresh token', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    $repository->revokeFamilyForRefreshToken('no-such-refresh');

    expect($grantStore->revocations)->toBe([]);
});

it('returns false from isRefreshTokenRevoked for a live bound refresh token', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    expect($repository->isRefreshTokenRevoked($family['refreshTokenId']))->toBeFalse();
});

it('S59: refuses refresh when the access token is revoked but the grant is still active', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    Passport::token()->newQuery()->whereKey($family['accessTokenId'])->update(['revoked' => true]);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    expect($repository->isRefreshTokenRevoked($family['refreshTokenId']))->toBeTrue()
        ->and($grantStore->find($family['grant']->id)?->revoked)->toBeTrue();
});

it('throws invalid_grant with the invalid_grant error type on CAS miss', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    $repository->revokeRefreshToken($family['refreshTokenId']);

    try {
        $repository->revokeRefreshToken($family['refreshTokenId']);
        expect(false)->toBeTrue('expected OAuthServerException');
    } catch (OAuthServerException $exception) {
        expect($exception->getErrorType())->toBe('invalid_grant')
            ->and($exception->getHint())->toBe('Refresh token reuse detected');
    }
});

it('throws invalid_grant when CAS wins but the bound grant was already reuse-revoked', function (): void {
    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $repository = app(FamilyRevokingRefreshTokenRepository::class);

    // Simulate League: old AT revoked before revokeRefreshToken.
    Passport::token()->newQuery()->whereKey($family['accessTokenId'])->update(['revoked' => true]);

    // Concurrent loser already wiped the grant (family revoke) before the CAS winner returns.
    $grantStore->revoke($family['grant']->id, null, RevocationReason::Reuse);

    try {
        $repository->revokeRefreshToken($family['refreshTokenId']);
        expect(false)->toBeTrue('expected OAuthServerException');
    } catch (OAuthServerException $exception) {
        expect($exception->getErrorType())->toBe('invalid_grant')
            ->and($exception->getHint())->toBe('Refresh token family has been revoked')
            ->and(Passport::refreshToken()->newQuery()->whereKey($family['refreshTokenId'])->value('revoked'))->toBeTrue();
    }
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

    expect(fn () => $repository->revokeRefreshToken($oldFamily['refreshTokenId']))
        ->toThrow(OAuthServerException::class);

    expect($grantStore->find('grant-old')?->revoked)->toBeTrue()
        ->and($grantStore->find('grant-new')?->revoked)->toBeFalse()
        ->and(Passport::token()->newQuery()->whereKey('access-token-new')->value('revoked'))->toBeFalse();
});

it('stops the League-order race loser before any new tokens are issued', function (): void {
    if (! function_exists('pcntl_fork') || ! function_exists('pcntl_waitpid')) {
        expect(function_exists('pcntl_fork'))->toBeTrue('pcntl is required for the parallel race test');

        return;
    }

    $defaultConnection = (string) config('database.default');
    $sqliteRacePath = null;

    // CI Databases (mysql|pgsql) use the default connection. SQLite :memory: is
    // not shareable across forks, so fall back to a WAL file for that engine.
    if ($defaultConnection === 'sqlite') {
        $sqliteRacePath = tempnam(sys_get_temp_dir(), 'mcp-oauth-race-');
        expect($sqliteRacePath)->not->toBeFalse();
        config([
            'passport.connection' => 'sqlite_race',
            'database.connections.sqlite_race' => [
                'driver' => 'sqlite',
                'database' => $sqliteRacePath,
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
            $table->string('id', 80)->primary();
            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->uuid('client_id');
            $table->string('name')->nullable();
            $table->text('scopes')->nullable();
            $table->boolean('revoked');
            $table->string('api_key_id')->nullable()->index();
            $table->timestamps();
            $table->dateTime('expires_at')->nullable();
        });
        Schema::connection('sqlite_race')->create('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->string('id', 80)->primary();
            $table->string('access_token_id', 80)->index();
            $table->boolean('revoked');
            $table->dateTime('expires_at')->nullable();
        });
    }

    /** @var FakeGrantStore $grantStore */
    $grantStore = app(GrantStore::class);
    $family = seedBoundFamily($grantStore);
    $refreshTokenId = $family['refreshTokenId'];
    $clientId = $family['grant']->clientId;
    $grantId = $family['grant']->id;

    $barrierPath = tempnam(sys_get_temp_dir(), 'mcp-oauth-barrier-');
    $resultDir = sys_get_temp_dir().'/mcp-oauth-race-'.bin2hex(random_bytes(4));
    mkdir($resultDir);
    expect($barrierPath)->not->toBeFalse();
    file_put_contents($barrierPath, '0');

    // Drop the parent's handle so forked children are not sharing a locked PDO.
    if ($sqliteRacePath !== null) {
        DB::connection('sqlite_race')->statement('PRAGMA busy_timeout=30000;');
        DB::disconnect('sqlite_race');
    } else {
        DB::disconnect($defaultConnection);
    }

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

            if ($sqliteRacePath !== null) {
                DB::purge('sqlite_race');
                DB::reconnect('sqlite_race');
                DB::connection('sqlite_race')->statement('PRAGMA busy_timeout=30000;');
            } else {
                DB::purge($defaultConnection);
                DB::reconnect($defaultConnection);
            }

            $prefix = 'fork-child'.$childIndex;
            $outcome = 'lost';

            try {
                // League: AT revoke then RT revoke; then issue only if revoke returns.
                Passport::token()->newQuery()->whereKey($family['accessTokenId'])->update(['revoked' => true]);
                app(FamilyRevokingRefreshTokenRepository::class)->revokeRefreshToken($refreshTokenId);
                issueTokensAfterRevoke($prefix, $clientId, $grantId);
                $outcome = 'won';
            } catch (Throwable) {
                // OAuth invalid_grant, or engine lock contention: never issue.
                $outcome = 'lost';
            }

            file_put_contents($resultDir.'/'.$prefix.'.txt', $outcome);
            posix_kill(getmypid(), SIGKILL);
            exit(0);
        }

        $childPids[] = $childPid;
    }

    foreach ($childPids as $childPid) {
        pcntl_waitpid($childPid, $status);
    }

    if ($sqliteRacePath !== null) {
        DB::purge('sqlite_race');
        DB::reconnect('sqlite_race');
    } else {
        DB::purge($defaultConnection);
        DB::reconnect($defaultConnection);
    }

    $outcomes = [];

    foreach (['fork-child0', 'fork-child1'] as $prefix) {
        $outcomes[$prefix] = trim((string) file_get_contents($resultDir.'/'.$prefix.'.txt'));
    }

    $winners = array_keys(array_filter($outcomes, static fn (string $outcome): bool => $outcome === 'won'));
    $losers = array_keys(array_filter($outcomes, static fn (string $outcome): bool => $outcome === 'lost'));

    expect($losers)->not->toBeEmpty('at least one race participant must lose the CAS')
        ->and(count($winners))->toBeLessThanOrEqual(1);

    foreach ($losers as $loserPrefix) {
        expect(Passport::token()->newQuery()->whereKey($loserPrefix.'-new-at')->exists())->toBeFalse(
            'race loser must not persist an access token',
        )->and(Passport::refreshToken()->newQuery()->whereKey($loserPrefix.'-new-rt')->exists())->toBeFalse(
            'race loser must not persist a refresh token',
        );
    }

    config(['passport.connection' => null]);
    @unlink($barrierPath);

    foreach (glob($resultDir.'/*') ?: [] as $resultFile) {
        @unlink($resultFile);
    }
    @rmdir($resultDir);

    if ($sqliteRacePath !== null) {
        @unlink($sqliteRacePath);
        @unlink($sqliteRacePath.'-wal');
        @unlink($sqliteRacePath.'-shm');
    }
});
