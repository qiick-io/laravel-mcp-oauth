<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Passport\AuthCode;
use Laravel\Passport\Passport;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use Qiick\McpOAuth\Actions\PurgeRevokedRecordsAction;
use Qiick\McpOAuth\Erasure\McpOAuthEraser;
use Qiick\McpOAuth\Erasure\OrganisationScopeUnsupportedException;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Tests\Support\TestUser;

it('explains why organisation-scoped erasure is refused', function (): void {
    expect(fn () => app(McpOAuthEraser::class)->erase('42', (string) Str::uuid(), McpOAuthEraser::DELETE, organisationId: (string) Str::uuid()))
        ->toThrow(OrganisationScopeUnsupportedException::class, 'MCP OAuth stores do not support organisation-scoped erasure.');
});

it('retains the decision through its existing or newly started retention window', function (): void {
    $this->freezeSecond();
    $user = TestUser::query()->create();
    $userId = (string) $user->getKey();
    $userPublicId = (string) Str::uuid();
    $clientId = (string) Str::uuid();
    $approval = OAuthConsentRecord::query()->create([
        'client_id' => $clientId,
        'user_identifier' => $userId,
        'grant_id' => (string) Str::uuid(),
        'decision' => 'approved',
        'redirect_uri' => 'https://client.example.test/callback',
        'redirect_host' => 'client.example.test',
        'requested_scopes' => ['mcp:use'],
        'all_resources' => true,
    ]);
    $denial = OAuthConsentRecord::query()->create([
        'client_id' => $clientId,
        'user_identifier' => $userId,
        'decision' => 'denied',
        'redirect_uri' => 'https://client.example.test/callback',
        'redirect_host' => 'client.example.test',
        'requested_scopes' => ['mcp:use'],
        'retention_until' => now()->addDays(10),
    ]);

    $report = app(McpOAuthEraser::class)->erase($userId, $userPublicId, McpOAuthEraser::DELETE);

    expect($report->changed())->toBe(2)
        ->and($report->toArray())->toBe([
            'package' => 'qiick/laravel-mcp-oauth',
            'mode' => McpOAuthEraser::DELETE,
            'dry_run' => false,
            'stores' => $report->stores,
        ])
        ->and($report->stores['oauth_consent_records'])->toBe([
            'deleted' => 0, 'anonymised' => 2, 'kept' => 2, 'reason' => 'consent_evidence',
        ])
        ->and(TestUser::query()->whereKey($userId)->exists())->toBeTrue();
    $approval->refresh();
    $denial->refresh();
    expect($approval->decision)->toBe('approved')
        ->and($approval->user_identifier)->toBeNull()
        ->and($approval->all_resources)->toBeFalse()
        ->and($approval->retention_until->equalTo(now()->addDays(90)))->toBeTrue()
        ->and($denial->decision)->toBe('denied')
        ->and($denial->retention_until->equalTo(now()->addDays(10)))->toBeTrue();

    $this->travel(10)->days();
    $purge = app(PurgeRevokedRecordsAction::class);
    $purge->execute(isDryRun: false);
    expect(OAuthConsentRecord::query()->count())->toBe(2);

    $this->travel(1)->seconds();
    $purge->execute(isDryRun: false);
    expect(OAuthConsentRecord::query()->pluck('decision')->all())->toBe(['approved']);
});

it('refuses erasure when a Passport credential store uses another connection', function (string $store): void {
    config(['database.connections.erasure_split' => ['driver' => 'sqlite', 'database' => ':memory:']]);
    $authCodeModel = Passport::authCodeModel();
    $tokenModel = Passport::tokenModel();
    $refreshTokenModel = Passport::refreshTokenModel();

    try {
        match ($store) {
            'authorization codes' => Passport::useAuthCodeModel((new class extends AuthCode
            {
                protected $connection = 'erasure_split';
            })::class),
            'access tokens' => Passport::useTokenModel((new class extends Token
            {
                protected $connection = 'erasure_split';
            })::class),
            'refresh tokens' => Passport::useRefreshTokenModel((new class extends RefreshToken
            {
                protected $connection = 'erasure_split';
            })::class),
        };

        expect(fn () => app(McpOAuthEraser::class)->erase('42', (string) Str::uuid(), McpOAuthEraser::DELETE, dryRun: true))
            ->toThrow(LogicException::class, 'MCP OAuth erasure requires its stores to share a database connection.');
    } finally {
        Passport::useAuthCodeModel($authCodeModel);
        Passport::useTokenModel($tokenModel);
        Passport::useRefreshTokenModel($refreshTokenModel);
        DB::purge('erasure_split');
    }
})->with(['authorization codes', 'access tokens', 'refresh tokens']);

it('keeps textual identity matching and only adds the bigint lookup for canonical keys', function (string $driver, string $userId, string $sqlType, array $bindings): void {
    $defaultConnection = DB::getDefaultConnection();
    $passportConnection = config('passport.connection');
    config([
        'database.connections.erasure_probe' => ['driver' => 'erasure_probe'],
        'passport.connection' => 'erasure_probe',
    ]);
    // Use a local PDO for the transaction and capture the queries without executing them.
    DB::extend('erasure_probe', fn () => new SQLiteConnection(new PDO('sqlite::memory:'), ':memory:', config: ['driver' => $driver]));
    DB::setDefaultConnection('erasure_probe');

    try {
        $hostQuery = null;
        $connection = DB::connection();
        $connection->listen(function (QueryExecuted $query) use ($connection, &$hostQuery): void {
            if ($query->connection === $connection && str_contains($query->sql, 'oauth_blocked_redirect_hosts')) {
                $hostQuery = $query;
            }
        });
        $connection->pretend(fn () => app(McpOAuthEraser::class)->erase(
            $userId, (string) Str::uuid(), McpOAuthEraser::DELETE, dryRun: true,
        ));

        expect($hostQuery)->toBeInstanceOf(QueryExecuted::class)
            ->and($hostQuery->sql)->toContain('cast(created_by as '.$sqlType.') = ?')
            ->and($hostQuery->bindings)->toBe($bindings);
    } finally {
        DB::setDefaultConnection($defaultConnection);
        config(['passport.connection' => $passportConnection]);
        DB::purge('erasure_probe');
    }
})->with([
    'SQLite canonical key' => ['sqlite', '42', 'text', ['42', '42']],
    'MySQL leading zeros' => ['mysql', '0042', 'char', ['0042']],
    'MariaDB UUID' => ['mariadb', 'd6908b27-1ee5-456e-aa31-7944435476a7', 'char', ['d6908b27-1ee5-456e-aa31-7944435476a7']],
]);

it('erases both orphaned and legacy code exchanges while leaving unrelated Passport credentials', function (): void {
    $user = TestUser::query()->create();
    $userId = (string) $user->getKey();
    $mcpClientId = (string) Str::uuid();
    $externalClientId = (string) Str::uuid();
    $grantId = (string) Str::uuid();
    $mcpCodeId = Str::random(80);
    $externalCodeId = Str::random(80);
    OAuthClientMetadata::query()->create(['client_id' => $mcpClientId, 'registration_source' => 'admin']);

    DB::table('oauth_auth_codes')->insert([
        ['id' => $mcpCodeId, 'user_id' => $userId, 'client_id' => $mcpClientId, 'revoked' => true],
        ['id' => $externalCodeId, 'user_id' => $userId, 'client_id' => $externalClientId, 'revoked' => false],
    ]);
    OAuthAuthCodeExchange::query()->create(['auth_code_id' => $mcpCodeId, 'grant_id' => (string) Str::uuid()]);
    OAuthAuthCodeExchange::query()->create(['auth_code_id' => 'legacy-orphan', 'grant_id' => $grantId]);
    OAuthAuthCodeExchange::query()->create([
        'auth_code_id' => 'attributed-orphan', 'grant_id' => (string) Str::uuid(), 'user_identifier' => $userId,
    ]);

    $report = app(McpOAuthEraser::class)->erase($userId, (string) Str::uuid(), McpOAuthEraser::ANONYMISE, [$grantId]);

    expect($report->stores['oauth_auth_code_exchanges']['deleted'])->toBe(3)
        ->and(OAuthAuthCodeExchange::query()->count())->toBe(0)
        ->and(DB::table('oauth_auth_codes')->pluck('id')->all())->toBe([$externalCodeId]);
});
