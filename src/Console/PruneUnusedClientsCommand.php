<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Console;

use Illuminate\Console\Command;
use Qiick\McpOAuth\Actions\PruneUnusedClientsAction;

/**
 * Products schedule it hourly: `Schedule::command('mcp-oauth:prune-unused-clients')->hourly()->onOneServer()`.
 *
 * @api
 */
final class PruneUnusedClientsCommand extends Command
{
    protected $signature = 'mcp-oauth:prune-unused-clients {--dry-run : Count the clients without deleting them}';

    protected $description = 'Delete DCR clients that nobody authorised within the unused-client window';

    public function handle(PruneUnusedClientsAction $pruneUnusedClients): int
    {
        $isDryRun = $this->option('dry-run') === true;
        $prune = $pruneUnusedClients->execute($isDryRun);

        $this->info(($isDryRun ? 'Would prune' : 'Pruned')." {$prune->clientCount} unused clients registered before {$prune->cutoff->format(DATE_ATOM)}.");

        return self::SUCCESS;
    }
}
