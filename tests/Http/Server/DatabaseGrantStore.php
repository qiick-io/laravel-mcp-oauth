<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Http\Server;

use DateTimeImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\Data\RevocationReason;

/**
 * A product's grant table, as small as the contract allows. The `php -S`
 * workers share nothing but the database, so the in-memory FakeGrantStore
 * cannot serve the `http` group.
 */
final class DatabaseGrantStore implements GrantStore
{
    public const string TABLE = 'http_flow_grants';

    public function find(string $grantId): ?GrantRecord
    {
        $row = DB::table(self::TABLE)->where('id', $grantId)->first();

        return $row === null ? null : self::recordFrom($row);
    }

    public function activeFor(string $clientId, string $userIdentifier): ?GrantRecord
    {
        $row = DB::table(self::TABLE)
            ->where('client_id', $clientId)
            ->where('user_identifier', $userIdentifier)
            ->where('revoked', false)
            ->orderByDesc('authorized_at')
            ->first();

        return $row === null ? null : self::recordFrom($row);
    }

    public function replace(ConsentDecision $decision): GrantRecord
    {
        return DB::transaction(function () use ($decision): GrantRecord {
            DB::table(self::TABLE)
                ->where('client_id', $decision->clientId)
                ->where('user_identifier', $decision->userIdentifier)
                ->where('revoked', false)
                ->lockForUpdate()
                ->update(['revoked' => true, 'revocation_reason' => RevocationReason::Reconsent->value, 'revoked_at' => now()]);

            $grantId = (string) Str::uuid7();
            DB::table(self::TABLE)->insert([
                'id' => $grantId,
                'client_id' => $decision->clientId,
                'user_identifier' => $decision->userIdentifier,
                'revoked' => false,
                'scopes' => json_encode($decision->scopes),
                'resource_scopes' => json_encode($decision->resourceScopes, JSON_THROW_ON_ERROR),
                'authorized_at' => now(),
            ]);

            return $this->find($grantId) ?? throw new \LogicException('The grant just written is missing.');
        });
    }

    public function revoke(string $grantId, ?string $actorIdentifier, RevocationReason $reason): void
    {
        DB::table(self::TABLE)
            ->where('id', $grantId)
            ->where('revoked', false)
            ->update(['revoked' => true, 'revocation_reason' => $reason->value, 'revoked_at' => now()]);
    }

    public function revokeAllForClient(string $clientId, ?string $actorIdentifier): void
    {
        DB::table(self::TABLE)
            ->where('client_id', $clientId)
            ->where('revoked', false)
            ->update(['revoked' => true, 'revocation_reason' => RevocationReason::Admin->value, 'revoked_at' => now()]);
    }

    public function everAuthorized(array $clientIds): array
    {
        /** @var list<string> $authorizedClientIds */
        $authorizedClientIds = DB::table(self::TABLE)->whereIn('client_id', $clientIds)->distinct()->pluck('client_id')->all();

        return $authorizedClientIds;
    }

    public function activeForUser(Authenticatable $user): array
    {
        /** @var int|string $authIdentifier */
        $authIdentifier = $user->getAuthIdentifier();

        return DB::table(self::TABLE)
            ->where('user_identifier', (string) $authIdentifier)
            ->where('revoked', false)
            ->get()
            ->map(static fn (object $row): GrantRecord => self::recordFrom($row))
            ->values()
            ->all();
    }

    public function purgeRevokedBefore(DateTimeImmutable $cutoff): int
    {
        return DB::table(self::TABLE)->where('revoked', true)->where('revoked_at', '<', $cutoff)->delete();
    }

    public function bindingKey(GrantRecord $grant): string
    {
        return $grant->id;
    }

    private static function recordFrom(object $row): GrantRecord
    {
        /** @var object{id: string, client_id: string, user_identifier: string, revoked: bool|int|string, scopes: string, resource_scopes: string, authorized_at: string} $row */
        /** @var list<string> $scopes */
        $scopes = json_decode($row->scopes, true);
        /** @var array<string, string> $resourceScopes */
        $resourceScopes = json_decode($row->resource_scopes, true, flags: JSON_THROW_ON_ERROR);

        return new GrantRecord(
            id: $row->id,
            clientId: $row->client_id,
            userIdentifier: $row->user_identifier,
            revoked: (bool) $row->revoked,
            scopes: $scopes,
            authorizedAt: new DateTimeImmutable($row->authorized_at),
            lastUsedAt: null,
            resourceScopes: $resourceScopes,
        );
    }
}
