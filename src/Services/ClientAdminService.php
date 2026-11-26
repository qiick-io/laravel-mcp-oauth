<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use DateTimeInterface;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * What the admin clients page reads (design §5.2): the clients this package
 * registered, newest first and paginated, and the blocked hosts. Public ids
 * and display hosts only; never a secret.
 *
 * @internal
 */
final class ClientAdminService
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly RedirectUriGuard $redirectUriGuard,
    ) {}

    /**
     * Passport clients that have a metadata row: the product's own Passport
     * clients are not MCP clients and never listed or blocked here.
     *
     * @return Builder<Client>
     */
    public static function packageClients(): Builder
    {
        /** @var Builder<Client> $clients */
        $clients = Passport::client()->newQuery()->whereIn('id', OAuthClientMetadata::query()->select('client_id'));

        return $clients;
    }

    /**
     * @return LengthAwarePaginator<int, array{id: string, name: string, redirectHosts: list<string>, isRevoked: bool, hasEverAuthorized: bool, createdAt: string|null}>
     */
    public function clients(): LengthAwarePaginator
    {
        // shortcut: a fixed page size; add a validated ?per_page when a page needs one.
        $clientPage = self::packageClients()->orderByDesc('created_at')->orderByDesc('id')->paginate(50);
        /** @var list<string> $clientIdsOnPage Passport client ids are UUID strings */
        $clientIdsOnPage = $clientPage->getCollection()->modelKeys();
        // The product's grants, or the approval mark that outlives their purge.
        $everAuthorizedClientIds = [
            ...$this->grantStore->everAuthorized($clientIdsOnPage),
            ...OAuthClientMetadata::query()->whereIn('client_id', $clientIdsOnPage)->whereNotNull('first_authorized_at')->pluck('client_id')->all(),
        ];

        return $clientPage->through(function (Client $client) use ($everAuthorizedClientIds): array {
            /** @var array{id: string, name: string, revoked: bool} $clientRow */
            $clientRow = $client->only(['id', 'name', 'revoked']);

            return [
                'id' => $clientRow['id'],
                'name' => $clientRow['name'],
                'redirectHosts' => $this->redirectHostsOf($client),
                'isRevoked' => $clientRow['revoked'],
                'hasEverAuthorized' => in_array($clientRow['id'], $everAuthorizedClientIds, true),
                'createdAt' => self::iso8601($client->getAttribute('created_at')),
            ];
        });
    }

    /**
     * @return list<array{id: string|null, host: string, matchMode: string, reason: mixed, expiresAt: string|null, createdAt: string|null}>
     */
    public function blockedHosts(): array
    {
        /** @var list<array{id: string|null, host: string, matchMode: string, reason: mixed, expiresAt: string|null, createdAt: string|null}> $blockedHosts */
        $blockedHosts = OAuthBlockedRedirectHost::query()->orderBy('host')->get()->map(
            static fn (OAuthBlockedRedirectHost $blockedHost): array => [
                'id' => $blockedHost->public_id,
                'host' => $blockedHost->host,
                'matchMode' => $blockedHost->match_mode,
                'reason' => $blockedHost->getAttribute('reason'),
                'expiresAt' => self::iso8601($blockedHost->getAttribute('expires_at')),
                'createdAt' => self::iso8601($blockedHost->getAttribute('created_at')),
            ],
        )->all();

        return $blockedHosts;
    }

    private static function iso8601(mixed $dateTime): ?string
    {
        return $dateTime instanceof DateTimeInterface ? $dateTime->format(DATE_ATOM) : null;
    }

    /**
     * @return list<string>
     */
    private function redirectHostsOf(Client $client): array
    {
        /** @var list<string> $redirectUris Passport's accessor always returns a list */
        $redirectUris = $client->getAttribute('redirect_uris');
        $displayHosts = array_map($this->redirectUriGuard->displayHostOf(...), $redirectUris);

        return array_values(array_unique($displayHosts));
    }
}
