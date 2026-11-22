<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Illuminate\Contracts\Auth\Authenticatable;
use LogicException;

/**
 * The user identifier Passport writes on auth codes and tokens
 * (`Bridge\User` = the auth identifier), as the string GrantStore,
 * ConsentDecision and consent records use.
 */
final class PassportUserIdentifier
{
    /**
     * @throws LogicException when the auth identifier is neither a string nor an int
     */
    public static function of(Authenticatable $user): string
    {
        $authIdentifier = $user->getAuthIdentifier();

        if (is_int($authIdentifier) || is_string($authIdentifier)) {
            return (string) $authIdentifier;
        }

        throw new LogicException('The user auth identifier must be a string or an integer.');
    }
}
