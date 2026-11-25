<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * Prop shape the default ConsentView renders for the authorize page.
 *
 * @api
 */
final readonly class ConsentPage
{
    /**
     * @param  array{id: string, name: string, redirectHost: string, nameIsSelfAsserted: true, isRedirectLoopback: bool}  $client
     */
    public function __construct(
        public array $client,
        public string $authToken,
        public ConsentOptions $options,
    ) {}
}
