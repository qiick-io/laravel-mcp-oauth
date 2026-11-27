<?php

declare(strict_types=1);

use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Events\McpClientBlockedEvent;
use Qiick\McpOAuth\Events\McpClientRegisteredEvent;
use Qiick\McpOAuth\Events\McpConsentApprovedEvent;
use Qiick\McpOAuth\Events\McpConsentDeniedEvent;
use Qiick\McpOAuth\Events\McpGrantRevokedEvent;
use Qiick\McpOAuth\Events\McpOAuthDisabledEvent;
use Qiick\McpOAuth\Events\McpOAuthEnabledEvent;
use Qiick\McpOAuth\Events\McpPassportKeysFoundMissingEvent;
use Qiick\McpOAuth\Events\McpRedirectHostBlockedEvent;
use Qiick\McpOAuth\Events\McpRedirectHostUnblockedEvent;
use Qiick\McpOAuth\Events\McpRefreshTokenReusedEvent;
use Qiick\McpOAuth\Events\McpUnusedClientsPrunedEvent;

it('builds every design event with string ids and hosts only', function (): void {
    expect(new McpOAuthEnabledEvent('user-uuid'))->actorIdentifier->toBe('user-uuid')
        ->and(new McpOAuthDisabledEvent(null))->actorIdentifier->toBeNull()
        ->and(new McpClientRegisteredEvent('client-uuid', ['app.example']))->displayHosts->toBe(['app.example'])
        ->and(new McpConsentApprovedEvent(
            'client-uuid',
            'user-uuid',
            'grant-uuid',
            'app.example',
            ['mcp:read'],
            ['area:public'],
        ))->grantId->toBe('grant-uuid')
        ->and(new McpConsentDeniedEvent('client-uuid', 'user-uuid'))->clientId->toBe('client-uuid')
        ->and(new McpGrantRevokedEvent(
            'grant-uuid',
            'client-uuid',
            'user-uuid',
            'admin-uuid',
            RevocationReason::Admin,
        ))->reason->toBe(RevocationReason::Admin)
        ->and(new McpRefreshTokenReusedEvent('client-uuid', 'user-uuid', 'grant-uuid', 3))->revokedTokenCount->toBe(3)
        ->and(new McpClientBlockedEvent('client-uuid', 'admin-uuid'))->clientId->toBe('client-uuid')
        ->and(new McpRedirectHostBlockedEvent('evil.test', 'admin-uuid'))->host->toBe('evil.test')
        ->and(new McpRedirectHostUnblockedEvent('evil.test', null))->host->toBe('evil.test')
        ->and(new McpUnusedClientsPrunedEvent(2, '2026-11-22T00:00:00+00:00'))->count->toBe(2)
        ->and(new McpPassportKeysFoundMissingEvent('/oauth/authorize', 'file_mode'))->reason->toBe('file_mode');
});
