<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User;

/**
 * Minimal authenticatable on the Testbench `users` table, so the authorize
 * flow can sign a real user in through the session guard. It must verify its
 * email like a product's user, so the `verified` middleware on approve and
 * deny is exercised rather than waved through.
 */
final class TestUser extends User implements MustVerifyEmail
{
    protected $table = 'users';

    protected $guarded = [];
}
