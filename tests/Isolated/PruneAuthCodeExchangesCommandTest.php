<?php

declare(strict_types=1);

use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * `mcp-oauth:prune-auth-code-exchanges`: a row is kept only while its grant is
 * active. Once the grant is revoked or gone, every token bound to it is
 * refused at use (design §8.5), so a replayed code has nothing left to
 * revoke. Age alone is no rule: refresh rotation keeps a grant's tokens alive
 * past any fixed window.
 */
function seedExchangesForEveryGrantState(AuthorizeFlowTestCase $testCase): void
{
    foreach (['active', 'revoked'] as $grantState) {
        $grantId = $grantState === 'active' ? '0195f0a0-0000-7000-8000-0000000000a1' : '0195f0a0-0000-7000-8000-0000000000a2';

        $testCase->grantStore()->seed(new GrantRecord(
            id: $grantId,
            clientId: '0195f0a0-0000-7000-8000-00000000c11e',
            userIdentifier: '1',
            revoked: false,
            scopes: ['mcp:read'],
            authorizedAt: null,
            lastUsedAt: null,
        ));

        if ($grantState === 'revoked') {
            $testCase->grantStore()->revoke($grantId, null, RevocationReason::User);
        }

        OAuthAuthCodeExchange::query()->create(['auth_code_id' => "code-of-{$grantState}-grant", 'grant_id' => $grantId]);
    }

    OAuthAuthCodeExchange::query()->create(['auth_code_id' => 'code-of-missing-grant', 'grant_id' => '0195f0a0-0000-7000-8000-0000000000a3']);
}

it('prunes the exchanges whose grant is revoked or gone and keeps the active one', function (): void {
    $this->enableOAuth();
    seedExchangesForEveryGrantState($this);

    $this->artisan('mcp-oauth:prune-auth-code-exchanges')
        ->expectsOutput('Pruned 2 authorization code exchanges.')
        ->assertSuccessful();

    expect(OAuthAuthCodeExchange::query()->pluck('auth_code_id')->all())->toBe(['code-of-active-grant']);
});

it('only counts with --dry-run', function (): void {
    $this->enableOAuth();
    seedExchangesForEveryGrantState($this);

    $this->artisan('mcp-oauth:prune-auth-code-exchanges', ['--dry-run' => true])
        ->expectsOutput('Would prune 2 authorization code exchanges.')
        ->assertSuccessful();

    expect(OAuthAuthCodeExchange::query()->count())->toBe(3);
});

it('works through more rows than one chunk', function (): void {
    $this->enableOAuth();

    foreach (range(1, 250) as $rowNumber) {
        OAuthAuthCodeExchange::query()->create([
            'auth_code_id' => sprintf('code-%03d', $rowNumber),
            'grant_id' => '0195f0a0-0000-7000-8000-0000000000a3',
        ]);
    }

    $this->artisan('mcp-oauth:prune-auth-code-exchanges')
        ->expectsOutput('Pruned 250 authorization code exchanges.')
        ->assertSuccessful();

    expect(OAuthAuthCodeExchange::query()->count())->toBe(0);
});
