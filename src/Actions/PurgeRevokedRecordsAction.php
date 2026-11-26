<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\Date;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\RevokedRecordsPurgeData;
use Qiick\McpOAuth\Events\McpRevokedRecordsPurgedEvent;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;

/**
 * Retention (standards review M5; decisions of 2026-11-22): what was revoked
 * more than `revoked_retention_days` (90) ago is deleted, and nothing sooner.
 * A row is kept for the full window: at exactly 90 days it stays.
 *
 * - **Clients** the package registered whose `revoked_at` is past the cutoff,
 *   with their codes and tokens. A product's own Passport client (no
 *   metadata row) is never touched.
 * - **Grants**, through GrantStore::purgeRevokedBefore(): the product deletes
 *   its own rows and may keep those it holds for its own reasons.
 * - **Consent records** past their `retention_until`. An approval whose grant
 *   is revoked or gone gets its clock started now (revocation + 90 days once
 *   GrantRecord carries the revocation time).
 *
 * A dry run counts the package's rows and leaves the product's grants alone.
 *
 * @internal
 */
final class PurgeRevokedRecordsAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly DeleteClientAction $deleteClient,
        private readonly ConfigRepository $config,
        private readonly Dispatcher $events,
    ) {}

    public function execute(bool $isDryRun): RevokedRecordsPurgeData
    {
        $retentionDays = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.revoked_retention_days'),
            'revoked_retention_days',
            BoundedPositiveInt::REVOKED_RETENTION_DAYS_MAX,
        );
        $now = CarbonImmutable::instance(Date::now());
        $cutoff = $now->subDays($retentionDays);

        $clientCount = $this->purgeClients($cutoff, $isDryRun);
        $consentRecordCount = $this->purgeConsentRecords($now, $retentionDays, $isDryRun);

        if ($isDryRun) {
            return new RevokedRecordsPurgeData($clientCount, null, $consentRecordCount, $cutoff->toDateTimeImmutable());
        }

        $grantCount = $this->grantStore->purgeRevokedBefore($cutoff->toDateTimeImmutable());

        $this->events->dispatch(new McpRevokedRecordsPurgedEvent(
            clientCount: $clientCount,
            grantCount: $grantCount,
            consentRecordCount: $consentRecordCount,
            cutoffIso8601: $cutoff->toIso8601String(),
        ));

        return new RevokedRecordsPurgeData($clientCount, $grantCount, $consentRecordCount, $cutoff->toDateTimeImmutable());
    }

    private function purgeClients(CarbonImmutable $cutoff, bool $isDryRun): int
    {
        $expiredClients = OAuthClientMetadata::query()->where('revoked_at', '<', $cutoff);

        if ($isDryRun) {
            return $expiredClients->count();
        }

        $deletedCount = 0;

        // A page at a time (F9): deleting behind the key cursor is safe. The
        // count is of the clients deleted, not of those counted beforehand.
        $expiredClients->select(['id', 'client_id'])->chunkById(100, function (Collection $metadataRows) use (&$deletedCount): void {
            foreach ($metadataRows as $metadataRow) {
                /** @var string $clientId client ids are UUID strings */
                $clientId = $metadataRow->getAttribute('client_id');
                $this->deleteClient->execute($clientId);
                $deletedCount++;
            }
        });

        return $deletedCount;
    }

    private function purgeConsentRecords(CarbonImmutable $now, int $retentionDays, bool $isDryRun): int
    {
        // Mass queries: the model refuses update and delete, which guard the evidence from app code.
        $expiredRecords = OAuthConsentRecord::query()->where('retention_until', '<', $now);

        if ($isDryRun) {
            return $expiredRecords->count();
        }

        $expiredCount = 0;

        // A page of keys at a time (F9), so a backlog never locks the table.
        // Each delete checks the deadline again: one extended since the page
        // was read keeps its evidence.
        $expiredRecords->select('id')->chunkById(100, static function (Collection $expiredPage) use ($now, &$expiredCount): void {
            $expiredCount += OAuthConsentRecord::query()
                ->whereKey($expiredPage->modelKeys())
                ->where('retention_until', '<', $now)
                ->toBase()
                ->delete();
        });

        $openApprovals = OAuthConsentRecord::query()
            ->where('decision', 'approved')
            ->whereNull('retention_until')
            ->whereNotNull('grant_id')
            ->lazyById();

        foreach ($openApprovals as $approval) {
            /** @var string $grantId the query keeps approvals with a grant */
            $grantId = $approval->getAttribute('grant_id');

            if ($this->grantStore->find($grantId)?->revoked !== false) {
                OAuthConsentRecord::query()->whereKey($approval->getKey())->update(['retention_until' => $now->addDays($retentionDays)]);
            }
        }

        return $expiredCount;
    }
}
