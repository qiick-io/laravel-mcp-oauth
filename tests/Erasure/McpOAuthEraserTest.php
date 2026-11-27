<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Qiick\McpOAuth\Actions\PurgeRevokedRecordsAction;
use Qiick\McpOAuth\Erasure\McpOAuthEraser;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use Qiick\McpOAuth\Tests\Support\TestUser;

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
        ->and($report->stores['oauth_consent_records'])->toBe([
            'deleted' => 0, 'anonymised' => 2, 'kept' => 2, 'reason' => 'consent_evidence',
        ])
        ->and(TestUser::query()->whereKey($userId)->exists())->toBeTrue();
    $approval->refresh();
    $denial->refresh();
    expect($approval->decision)->toBe('approved')
        ->and($approval->user_identifier)->toBeNull()
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
