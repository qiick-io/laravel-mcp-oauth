<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

/**
 * Carries the grant selected by an authorization code exchange or installation
 * refresh to BindAccessTokenAction. A concurrent consent cannot switch the
 * token to another grant. A code consumed with no active grant is recorded too,
 * so its token is revoked even if consent appears afterwards. The instance is
 * scoped to one request.
 *
 * @internal
 */
final class ConsumedAuthCodeGrant
{
    private bool $isRecorded;

    private ?string $grantId;

    public function __construct()
    {
        $this->isRecorded = false;
        $this->grantId = null;
    }

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
