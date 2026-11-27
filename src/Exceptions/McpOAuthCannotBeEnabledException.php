<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Exceptions;

use RuntimeException;

/**
 * Switching OAuth on was refused (design §4.3); the message is the reason to
 * show the admin.
 *
 * @api
 */
final class McpOAuthCannotBeEnabledException extends RuntimeException {}
