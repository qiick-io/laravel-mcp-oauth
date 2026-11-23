<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

/**
 * The grant an authorization code was just consumed under, handed from
 * OneShotAuthCodeRepository to BindAccessTokenAction within one token
 * request, so the token is bound to that grant even if a newer consent lands
 * in between. A code consumed with no active grant is recorded too: its token
 * is revoked, never bound to a consent that appears afterwards. Bound as a
 * scoped instance: it never outlives the request.
 *
 * @internal
 */
final class ConsumedAuthCodeGrant
{
    private bool $isRecorded = false;

    private ?string $grantId = null;

    public function record(?string $grantId): void
    {
        $this->isRecorded = true;
        $this->grantId = $grantId;
    }

    public function isRecorded(): bool
    {
        return $this->isRecorded;
    }

    /**
     * Reads the grant id once, so a second token in the same request falls
     * back to the active grant.
     */
    public function take(): ?string
    {
        $grantId = $this->grantId;
        $this->isRecorded = false;
        $this->grantId = null;

        return $grantId;
    }
}
