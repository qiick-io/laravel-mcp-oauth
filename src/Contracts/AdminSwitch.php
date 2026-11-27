<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Contracts;

/**
 * Whether an admin has switched OAuth on. Read on every request; never cached
 * by the package.
 *
 * @api
 */
interface AdminSwitch
{
    /**
     * Must return false (not throw) when its store cannot be read.
     */
    public function enabled(): bool;
}
