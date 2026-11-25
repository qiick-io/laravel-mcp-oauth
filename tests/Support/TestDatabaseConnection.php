<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use Illuminate\Contracts\Config\Repository as ConfigRepository;

/**
 * The database a test runs on, chosen by DB_CONNECTION in the process
 * environment (design §11.3: `.env` does not override phpunit.xml). Shared by
 * the in-process suite and the `php -S` app of the `http` group, so both
 * always talk to the same engine.
 */
final class TestDatabaseConnection
{
    /**
     * @param  string  $sqliteDatabase  `:memory:` in process; a file the
     *                                  `php -S` workers share otherwise
     */
    public static function configure(ConfigRepository $config, string $sqliteDatabase): void
    {
        $connection = getenv('DB_CONNECTION') ?: 'sqlite';

        if ($connection === 'sqlite') {
            $config->set('database.default', 'sqlite');
            $config->set('database.connections.sqlite', [
                'driver' => 'sqlite',
                'database' => $sqliteDatabase,
                'prefix' => '',
                'foreign_key_constraints' => true,
                // Several workers write one file (S57): wait for the lock
                // instead of failing, and let readers run beside a writer.
                'busy_timeout' => 10_000,
                'journal_mode' => $sqliteDatabase === ':memory:' ? null : 'wal',
            ]);

            return;
        }

        $isPgsql = $connection === 'pgsql';
        $config->set('database.default', $connection);
        $config->set("database.connections.{$connection}", [
            'driver' => $connection === 'mariadb' ? 'mysql' : $connection,
            'host' => getenv('DB_HOST') ?: '127.0.0.1',
            'port' => getenv('DB_PORT') ?: ($isPgsql ? '5432' : '3306'),
            'database' => getenv('DB_DATABASE') ?: 'mcp_oauth_test',
            'username' => getenv('DB_USERNAME') ?: ($isPgsql ? 'postgres' : 'root'),
            'password' => getenv('DB_PASSWORD') !== false ? (string) getenv('DB_PASSWORD') : '',
            'charset' => $isPgsql ? 'utf8' : 'utf8mb4',
            'collation' => $isPgsql ? null : 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'search_path' => 'public',
        ]);
    }
}
