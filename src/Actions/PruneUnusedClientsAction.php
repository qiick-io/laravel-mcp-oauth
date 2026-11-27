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
use Qiick\McpOAuth\Events\McpUnusedClientsPrunedEvent;
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
 *
 * @internal
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

        if ($isDryRun) {
            return new UnusedClientsPruneData(count($unusedClientIds), $cutoff->toDateTimeImmutable());
        }

        $prunedClientCount = 0;

        foreach ($unusedClientIds as $clientId) {
            $prunedClientCount += $this->deleteIfStillUnused($clientId) ? 1 : 0;
        }

        $this->events->dispatch(new McpUnusedClientsPrunedEvent($prunedClientCount, $cutoff->toIso8601String()));

        return new UnusedClientsPruneData($prunedClientCount, $cutoff->toDateTimeImmutable());
    }

    /**
     * The selection above may be minutes old: a user may have approved the
     * client since (#31 review M1), or an admin blocked it. Re-read under a
     * row lock, in the transaction that deletes, so an approval committed
     * first keeps the client, and one that comes later waits for the delete.
     */
    private function deleteIfStillUnused(string $clientId): bool
    {
        /** @var bool $isDeleted Laravel 12 types transaction() as mixed */
        $isDeleted = OAuthClientMetadata::query()->getConnection()->transaction(function () use ($clientId): bool {
            $isStillUnused = OAuthClientMetadata::query()
                ->where('client_id', $clientId)
                ->whereNull('first_authorized_at')
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->exists();

            if ($isStillUnused) {
                $this->deleteClient->execute($clientId);
            }

            return $isStillUnused;
        });

        return $isDeleted;
    }
}
