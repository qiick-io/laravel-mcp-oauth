<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Console;

use Illuminate\Console\Command;
use Qiick\McpOAuth\Actions\PruneAuthCodeExchangesAction;

/**
 * Products schedule it daily: `Schedule::command('mcp-oauth:prune-auth-code-exchanges')->daily()->onOneServer()`.
 *
 * @api
 */
final class PruneAuthCodeExchangesCommand extends Command
{
    protected $signature = 'mcp-oauth:prune-auth-code-exchanges {--dry-run : Count the rows without deleting them}';

    protected $description = 'Delete the authorization code exchanges whose grant is revoked or gone';

    public function handle(PruneAuthCodeExchangesAction $pruneAuthCodeExchanges): int
    {
        $isDryRun = $this->option('dry-run') === true;
        $prunedCount = $pruneAuthCodeExchanges->execute($isDryRun);

        $this->info(($isDryRun ? 'Would prune' : 'Pruned')." {$prunedCount} authorization code exchanges.");

        return self::SUCCESS;
    }
}
