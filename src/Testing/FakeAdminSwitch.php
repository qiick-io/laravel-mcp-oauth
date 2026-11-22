<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Qiick\McpOAuth\Contracts\AdminSwitch;

/**
 * Test double for {@see AdminSwitch}. Set `$storeIsUnreadable` to simulate a
 * store that cannot be read: {@see enabled()} returns false and does not throw.
 */
final class FakeAdminSwitch implements AdminSwitch
{
    public function __construct(
        private readonly bool $isEnabled = false,
        private readonly bool $storeIsUnreadable = false,
    ) {}

    public function enabled(): bool
    {
        if ($this->storeIsUnreadable) {
            return false;
        }

        return $this->isEnabled;
    }
}
