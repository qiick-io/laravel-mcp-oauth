<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Qiick\McpOAuth\Contracts\AdminSwitch;

/**
 * Default AdminSwitch while the product has not bound its own. Always off.
 *
 * @internal
 */
final class DisabledAdminSwitch implements AdminSwitch
{
    public function enabled(): bool
    {
        return false;
    }
}
