<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * One grantable choice on the consent screen (scope, role or resource).
 *
 * @api
 */
final readonly class ConsentOption
{
    public function __construct(
        public string $value,
        public string $label,
        public bool $grantable,
        public ?string $description = null,
    ) {}
}
