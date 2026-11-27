<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Console;

use Illuminate\Console\Command;
use Qiick\McpOAuth\Actions\PurgeRevokedRecordsAction;

/**
 * Products schedule it daily: `Schedule::command('mcp-oauth:purge-revoked')->daily()->onOneServer()`.
 *
 * @internal
 */
final class PurgeRevokedRecordsCommand extends Command
{
    protected $signature = 'mcp-oauth:purge-revoked {--dry-run : Count the rows without deleting them}';

    protected $description = 'Delete the MCP OAuth clients, grants and consent records past the revoked retention window';

    public function handle(PurgeRevokedRecordsAction $purgeRevokedRecords): int
    {
        $isDryRun = $this->option('dry-run') === true;
        $purge = $purgeRevokedRecords->execute($isDryRun);
        $cutoff = $purge->cutoff->format(DATE_ATOM);

        $this->info($isDryRun
            ? "Would purge {$purge->clientCount} clients and {$purge->consentRecordCount} consent records revoked before {$cutoff}; product grants are purged only for real."
            : "Purged {$purge->clientCount} clients, {$purge->grantCount} grants and {$purge->consentRecordCount} consent records revoked before {$cutoff}.");

        return self::SUCCESS;
    }
}
