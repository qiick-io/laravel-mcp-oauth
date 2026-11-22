<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched when a request hits OAuth while Passport keys are missing.
 *
 * @api
 */
final readonly class McpPassportKeysMissing
{
    /**
     * @param  'env_pair_incomplete'|'file_mode'|'unreadable'  $reason
     */
    public function __construct(
        public string $endpoint,
        public string $reason,
    ) {}
}
