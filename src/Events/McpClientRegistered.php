<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Events;

/**
 * Dispatched after commit when DCR creates a client.
 *
 * @api
 */
final readonly class McpClientRegistered
{
    /**
     * @param  list<string>  $displayHosts
     */
    public function __construct(
        public string $clientId,
        public array $displayHosts,
    ) {}
}
