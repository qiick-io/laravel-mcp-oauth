<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Exceptions;

use RuntimeException;

/**
 * An OAuth request cannot use CIMD until discovery can be retried.
 *
 * @internal
 */
final class ClientMetadataUnavailableException extends RuntimeException {}
