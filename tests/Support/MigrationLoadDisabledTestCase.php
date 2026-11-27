<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Foundation\Application;

/**
 * Boots the package with mcp-oauth.migrations.load=false so the provider must
 * not register its migration path (apps that publish and own the files).
 */
class MigrationLoadDisabledTestCase extends PackageTestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('mcp-oauth.migrations.load', false);
    }

    protected function defineDatabaseMigrations(): void
    {
        // Provider must not load; this case only asserts migrator paths.
    }
}
