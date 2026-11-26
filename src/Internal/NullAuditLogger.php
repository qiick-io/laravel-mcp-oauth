<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Illuminate\Contracts\Auth\Authenticatable;
use Qiick\McpOAuth\Contracts\AuditLogger;

/**
 * The {@see AuditLogger} the package binds until the product binds its own
 * sink: audit is optional, so the package writes its entries either way and
 * this one drops them.
 */
final class NullAuditLogger implements AuditLogger
{
    public function record(string $event, ?Authenticatable $causer, ?string $grantId, array $properties): void {}
}
