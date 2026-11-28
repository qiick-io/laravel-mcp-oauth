<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * The new active grant and the grant its installation just replaced.
 *
 * @api
 */
final readonly class GrantReplacementData
{
    public function __construct(public GrantRecord $grant, public ?GrantRecord $previousGrant = null) {}
}
