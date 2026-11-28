<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Enums;

/**
 * Distinguishes a usable transport result from a terminal refusal or retryable failure.
 *
 * @api
 */
enum ClientMetadataFetchStatusEnum: string
{
    case Fetched = 'fetched';
    case NotModified = 'not_modified';
    case Invalid = 'invalid';
    case Unavailable = 'unavailable';
}
