<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Traits;

/**
 * For package models written beside Passport's rows (a client's metadata, a
 * consumed code's grant): they live on `passport.connection`, so one
 * transaction can cover both.
 *
 * @internal
 */
trait UsesPassportConnectionTrait
{
    public function getConnectionName(): ?string
    {
        $passportConnection = config('passport.connection');

        return is_string($passportConnection) ? $passportConnection : null;
    }
}
