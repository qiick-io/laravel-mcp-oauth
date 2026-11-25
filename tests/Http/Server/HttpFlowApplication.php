<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Http\Server;

use Illuminate\Foundation\Application;
use Laravel\Mcp\Server\McpServiceProvider;
use Laravel\Passport\PassportServiceProvider;
use Orchestra\Testbench\Foundation\Application as TestbenchApplication;
use Qiick\McpOAuth\McpOAuthServiceProvider;

/**
 * The Laravel app the `http` group serves with `php -S` (design §11.1):
 * Testbench's skeleton with Passport, laravel/mcp, this package and the test
 * product's adapters, nothing auto-discovered. Built once per request, as a
 * real server does, so no state survives between requests except the
 * database, the cache files and the cookies.
 */
final class HttpFlowApplication
{
    public static function create(): Application
    {
        return TestbenchApplication::create(options: ['extra' => [
            // First, so its config is in place before the package registers.
            'providers' => [
                HttpFlowServiceProvider::class,
                PassportServiceProvider::class,
                McpServiceProvider::class,
                McpOAuthServiceProvider::class,
            ],
            'dont-discover' => ['*'],
        ]]);
    }
}
