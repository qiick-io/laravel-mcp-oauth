<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Exceptions;

use RuntimeException;

/**
 * OAuth is on but Passport cannot sign or verify tokens. Surfaces as HTTP 503,
 * never a 500 from league/oauth2-server.
 *
 * @api
 */
final class MissingPassportKeysException extends RuntimeException
{
    public static function make(): self
    {
        return new self(
            'OAuth for MCP is enabled but Passport signing keys are missing. Run `php artisan passport:keys`, or set PASSPORT_PRIVATE_KEY and PASSPORT_PUBLIC_KEY.',
        );
    }
}
