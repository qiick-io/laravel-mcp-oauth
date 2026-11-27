<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Qiick\McpOAuth\Contracts\AdminSwitch;
use RuntimeException;

/**
 * Test double for {@see AdminSwitch}. Set `$storeIsUnreadable` to simulate a
 * store that cannot be read: {@see enabled()} returns false and does not throw.
 * Set `$throwsOnRead` for design §4.2 / S11 (a throwing switch must count as OFF).
 *
 * @api
 */
final class FakeAdminSwitch implements AdminSwitch
{
    public function __construct(
        private readonly bool $isEnabled = false,
        private readonly bool $storeIsUnreadable = false,
        private readonly bool $throwsOnRead = false,
    ) {}

    public function enabled(): bool
    {
        if ($this->throwsOnRead) {
            throw new RuntimeException('Admin switch store failed.');
        }

        if ($this->storeIsUnreadable) {
            return false;
        }

        return $this->isEnabled;
    }
}
