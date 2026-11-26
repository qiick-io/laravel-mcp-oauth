<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Events\McpRedirectHostUnblockedEvent;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;

/**
 * An admin lifts a host block. Clients the block revoked stay revoked: they
 * register again, and the user consents again.
 *
 * Dispatches {@see McpRedirectHostUnblockedEvent}.
 */
final class UnblockRedirectHostAction
{
    public function __construct(
        private readonly AuditLogger $auditLogger,
    ) {}

    public function execute(OAuthBlockedRedirectHost $blockedHost, ?Authenticatable $actor): void
    {
        // With its audit entry or not at all, so a failed unblock can be retried.
        $blockedHost->getConnection()->transaction(function () use ($blockedHost, $actor): void {
            $blockedHost->delete();
            $this->auditLogger->record('oauth_redirect_host_unblocked', $actor, null, ['host' => $blockedHost->host]);
        });

        event(new McpRedirectHostUnblockedEvent($blockedHost->host, $actor === null ? null : PassportUserIdentifier::of($actor)));
    }
}
