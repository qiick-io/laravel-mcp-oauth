<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Foundation\Auth\User;

/**
 * Minimal authenticatable on the Testbench `users` table, so the authorize
 * flow can sign a real user in through the session guard.
 */
final class TestUser extends User
{
    protected $table = 'users';

    protected $guarded = [];
}
