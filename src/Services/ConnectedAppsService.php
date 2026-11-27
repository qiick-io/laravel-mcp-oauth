<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * What the Connected apps page reads: the signed-in user's active grants
 * (GrantStore::activeForUser()), each with the client it was given to. A
 * grant whose client no longer exists is still listed, so the user can
 * revoke it.
 *
 * @internal
 */
final class ConnectedAppsService
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly RedirectUriGuard $redirectUriGuard,
    ) {}

    /**
     * @return list<array{id: string, client: array{id: string, name: string|null, redirectHosts: list<string>}, scopes: list<string>, display: array<string, mixed>, authorizedAt: string|null, lastUsedAt: string|null}>
     */
    public function forUser(Authenticatable $user): array
    {
        $grants = $this->grantStore->activeForUser($user);
        $clientsById = Passport::client()->newQuery()
            ->whereKey(array_map(static fn (GrantRecord $grant): string => $grant->clientId, $grants))
            ->get()
            ->keyBy('id');

        return array_map(fn (GrantRecord $grant): array => [
            'id' => $grant->id,
            'client' => $this->clientSummary($grant->clientId, $clientsById->get($grant->clientId)),
            'scopes' => $grant->scopes,
            'display' => $grant->display,
            'authorizedAt' => $grant->authorizedAt?->format(DateTimeInterface::ATOM),
            'lastUsedAt' => $grant->lastUsedAt?->format(DateTimeInterface::ATOM),
        ], $grants);
    }

    /**
     * The user's own active grant with this id, or null.
     */
    public function activeGrantOf(Authenticatable $user, string $grantId): ?GrantRecord
    {
        foreach ($this->grantStore->activeForUser($user) as $grant) {
            if ($grant->id === $grantId) {
                return $grant;
            }
        }

        return null;
    }

    /**
     * @return array{id: string, name: string|null, redirectHosts: list<string>}
     */
    private function clientSummary(string $clientId, ?Client $client): array
    {
        /** @var list<string> $redirectUris Passport's accessor always returns a list */
        $redirectUris = $client?->getAttribute('redirect_uris') ?? [];
        /** @var string|null $name */
        $name = $client?->getAttribute('name');

        return [
            'id' => $clientId,
            'name' => $name,
            'redirectHosts' => array_values(array_unique(array_map($this->redirectUriGuard->displayHostOf(...), $redirectUris))),
        ];
    }
}
