<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * Why a grant was revoked. Carried on events and audit only as this string.
 * Cases may be added before 1.0: a consumer's `match` needs a default arm.
 *
 * @api
 */
enum RevocationReason: string
{
    case User = 'user';
    case Admin = 'admin';
    case Reuse = 'reuse';
    case Reconsent = 'reconsent';
    case Owner = 'owner';
    /** The client revoked its refresh token (RFC 7009). */
    case Client = 'client';

    /** An automatic revocation for a security reason other than reuse. */
    case Security = 'security';
}
