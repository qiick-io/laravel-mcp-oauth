<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Date;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\UnusedClientsPruneData;
use Qiick\McpOAuth\Events\McpUnusedClientsPruned;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Models\OAuthClientMetadata;

/**
 * Deletes DCR clients registered more than `unused_client_retention_hours`
 * (24) ago that no user ever authorised, in chunks (design §5.4, S31). A
 * client counts as authorised when its metadata row has
 * `first_authorized_at`, which the retention purge never clears, or when the
 * product still lists a grant for it (GrantStore::everAuthorized(), a revoked
 * one included): a grant alone would be forgotten once purged. A client in
 * retention (`revoked_at` set) is left to `mcp-oauth:purge-revoked`, and a
 * product's own Passport client (no metadata row) is never touched.
 */
final class PruneUnusedClientsAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly DeleteClientAction $deleteClient,
        private readonly ConfigRepository $config,
        private readonly Dispatcher $events,
    ) {}

    public function execute(bool $isDryRun): UnusedClientsPruneData
    {
        $retentionHours = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.unused_client_retention_hours'),
            'unused_client_retention_hours',
            BoundedPositiveInt::UNUSED_CLIENT_RETENTION_HOURS_MAX,
        );
        $cutoff = CarbonImmutable::instance(Date::now())->subHours($retentionHours);
        $unusedClientIds = [];

        OAuthClientMetadata::query()
            ->where('registration_source', 'dcr')
            ->whereNull('revoked_at')
            ->whereNull('first_authorized_at')
            ->chunkById(100, function ($metadataRows) use ($cutoff, &$unusedClientIds): void {
                /** @var list<string> $clientIds client ids are UUID strings */
                $clientIds = $metadataRows->pluck('client_id')->all();
                /** @var list<string> $oldClientIds */
                $oldClientIds = Passport::client()->newQuery()
                    ->whereKey($clientIds)
                    ->where('created_at', '<', $cutoff)
                    ->pluck('id')
                    ->all();

                array_push($unusedClientIds, ...array_diff($oldClientIds, $this->grantStore->everAuthorized($oldClientIds)));
            });

        if (! $isDryRun) {
            foreach ($unusedClientIds as $clientId) {
                $this->deleteClient->execute($clientId);
            }

            $this->events->dispatch(new McpUnusedClientsPruned(count($unusedClientIds), $cutoff->toIso8601String()));
        }

        return new UnusedClientsPruneData(count($unusedClientIds), $cutoff->toDateTimeImmutable());
    }
}
