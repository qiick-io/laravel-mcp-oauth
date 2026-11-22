<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Audit sink. Ids only; never token material.
 *
 * @api
 */
interface AuditLogger
{
    /**
     * @param  array<string, scalar|list<scalar>|null>  $properties
     */
    public function record(string $event, ?Authenticatable $causer, ?string $grantId, array $properties): void;
}
