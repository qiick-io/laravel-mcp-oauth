<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\PassportServiceProvider;
use Orchestra\Testbench\Foundation\Application;
use Qiick\McpOAuth\Actions\PruneUnusedClientsAction;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\McpOAuthServiceProvider;
use Qiick\McpOAuth\Testing\FakeGrantStore;
use Qiick\McpOAuth\Tests\Support\TestDatabaseConnection;

/*
 * A second database session for the first-approval race tests: runs the real
 * PruneUnusedClientsAction on the engine named by DB_CONNECTION. With a
 * signal file and a hold time, it writes the file right after deleting a
 * client's metadata row and keeps its transaction (and the row lock) open for
 * that many seconds. With a selection file, it writes that file once it has
 * read the clients registered before the cutoff, before it locks any of them.
 * Prints how many clients it pruned.
 *
 * Usage: php tests/Support/prune-unused-clients.php [signal-file hold-seconds [selection-file]]
 */
require __DIR__.'/../../vendor/autoload.php';

[, $signalFile, $holdSeconds, $selectionFile] = $argv + [null, null, '0', null];

$app = Application::create(options: ['extra' => [
    'providers' => [PassportServiceProvider::class, McpOAuthServiceProvider::class],
    'dont-discover' => ['*'],
]]);
TestDatabaseConnection::configure($app['config'], ':memory:');
DB::purge();
$app->instance(GrantStore::class, new FakeGrantStore);

if (is_string($signalFile) && $signalFile !== '') {
    DB::listen(static function (QueryExecuted $query) use ($signalFile, $holdSeconds): void {
        if (str_starts_with(strtolower($query->sql), 'delete from') && str_contains($query->sql, 'oauth_client_metadata')) {
            file_put_contents($signalFile, 'locked');
            sleep((int) $holdSeconds);
        }
    });
}

if (is_string($selectionFile) && $selectionFile !== '') {
    DB::listen(static function (QueryExecuted $query) use ($selectionFile): void {
        if (str_starts_with(strtolower($query->sql), 'select') && str_contains($query->sql, 'oauth_clients') && str_contains($query->sql, 'created_at')) {
            file_put_contents($selectionFile, 'selected');
        }
    });
}

echo $app->make(PruneUnusedClientsAction::class)->execute(false)->clientCount;
