<?php

declare(strict_types=1);

use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpClientBlocked;
use Qiick\McpOAuth\Events\McpClientRegistered;
use Qiick\McpOAuth\Events\McpConsentApproved;
use Qiick\McpOAuth\Events\McpConsentDenied;
use Qiick\McpOAuth\Events\McpGrantRevoked;
use Qiick\McpOAuth\Events\McpOAuthDisabled;
use Qiick\McpOAuth\Events\McpOAuthEnabled;
use Qiick\McpOAuth\Events\McpPassportKeysMissing;
use Qiick\McpOAuth\Events\McpRedirectHostBlocked;
use Qiick\McpOAuth\Events\McpRedirectHostUnblocked;
use Qiick\McpOAuth\Events\McpRefreshTokenReused;
use Qiick\McpOAuth\Events\McpUnusedClientsPruned;

it('builds every design event with string ids and hosts only', function (): void {
    expect(new McpOAuthEnabled('user-uuid'))->actorIdentifier->toBe('user-uuid')
        ->and(new McpOAuthDisabled(null))->actorIdentifier->toBeNull()
        ->and(new McpClientRegistered('client-uuid', ['app.example']))->displayHosts->toBe(['app.example'])
        ->and(new McpConsentApproved(
            'client-uuid',
            'user-uuid',
            'grant-uuid',
            'app.example',
            ['mcp:read'],
            ['area:public'],
        ))->grantId->toBe('grant-uuid')
        ->and(new McpConsentDenied('client-uuid', 'user-uuid'))->clientId->toBe('client-uuid')
        ->and(new McpGrantRevoked(
            'grant-uuid',
            'client-uuid',
            'user-uuid',
            'admin-uuid',
            RevocationReason::Admin,
        ))->reason->toBe(RevocationReason::Admin)
        ->and(new McpRefreshTokenReused('client-uuid', 'user-uuid', 'grant-uuid', 3))->revokedTokenCount->toBe(3)
        ->and(new McpClientBlocked('client-uuid', 'admin-uuid'))->clientId->toBe('client-uuid')
        ->and(new McpRedirectHostBlocked('evil.test', 'admin-uuid'))->host->toBe('evil.test')
        ->and(new McpRedirectHostUnblocked('evil.test', null))->host->toBe('evil.test')
        ->and(new McpUnusedClientsPruned(2, '2026-11-22T00:00:00+00:00'))->count->toBe(2)
        ->and(new McpPassportKeysMissing('/oauth/authorize', 'file_mode'))->reason->toBe('file_mode');
});
