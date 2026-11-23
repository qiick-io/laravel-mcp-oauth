<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

/**
 * The grant an authorization code was just consumed under, handed from
 * OneShotAuthCodeRepository to BindAccessTokenAction within one token
 * request, so the token is bound to that grant even if a newer consent lands
 * in between. Bound as a scoped instance: it never outlives the request.
 *
 * @internal
 */
final class ConsumedAuthCodeGrant
{
    public ?string $grantId = null;

    /**
     * Reads the grant id once, so a second token in the same request falls
     * back to the active grant.
     */
    public function take(): ?string
    {
        $grantId = $this->grantId;
        $this->grantId = null;

        return $grantId;
    }
}
