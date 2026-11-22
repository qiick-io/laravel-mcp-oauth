<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Foundation\Application;
use Laravel\Passport\PassportServiceProvider;
use Qiick\McpOAuth\McpOAuthServiceProvider;

/**
 * Boots the package together with Passport so route registration and grant
 * wiring can be asserted against a real PassportServiceProvider.
 */
class PassportBootedTestCase extends PackageTestCase
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            McpOAuthServiceProvider::class,
            PassportServiceProvider::class,
        ];
    }
}
