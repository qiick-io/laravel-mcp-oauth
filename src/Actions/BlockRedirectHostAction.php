<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Events\McpRedirectHostBlocked;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * An admin blocks a redirect host (design §8.2, S39). The host is normalised
 * to ASCII (UTS #46; Unicode input accepted) and stored once; blocking it
 * again keeps the first row, its match mode and reason included: unblock,
 * then block again, to change them. Then, outside any transaction, so a large client
 * table never holds a lock open, every non-revoked client whose redirect URIs
 * the block now matches is blocked with {@see BlockClientAction}, in chunks
 * of `host_block_chunk_size`.
 *
 * The block also takes effect without that loop: authorize, token and every
 * `/mcp` call re-check the client's hosts. The loop makes it stick after an
 * unblock.
 *
 * Dispatches {@see McpRedirectHostBlocked} once the row is written.
 */
final class BlockRedirectHostAction
{
    public function __construct(
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly BlockClientAction $blockClientAction,
        private readonly ConfigRepository $config,
        private readonly AuditLogger $auditLogger,
    ) {}

    /**
     * @throws InvalidArgumentException when the host does not normalise
     */
    public function execute(string $host, ?Authenticatable $actor, bool $isSubdomainMatched, ?string $reason = null): OAuthBlockedRedirectHost
    {
        $normalizedHost = $this->redirectUriGuard->normalizeHost($host);

        // One short transaction for the row and its audit entry (design §8.2).
        /** @var OAuthBlockedRedirectHost $blockedHost Laravel 12 types transaction() as mixed */
        $blockedHost = OAuthBlockedRedirectHost::query()->getConnection()->transaction(function () use ($normalizedHost, $host, $actor, $isSubdomainMatched, $reason): OAuthBlockedRedirectHost {
            $blockedHost = OAuthBlockedRedirectHost::query()->firstOrCreate(['host' => $normalizedHost], [
                'host_original' => $host,
                'match_mode' => $isSubdomainMatched ? 'host_and_subdomains' : OAuthBlockedRedirectHost::MATCH_MODE_EXACT,
                'reason' => $reason,
                'created_by' => $actor?->getAuthIdentifier(),
            ]);
            $this->auditLogger->record('oauth_redirect_host_blocked', $actor, null, ['host' => $normalizedHost, 'match_mode' => $blockedHost->match_mode]);

            return $blockedHost;
        });

        event(new McpRedirectHostBlocked($normalizedHost, $actor === null ? null : PassportUserIdentifier::of($actor)));

        $chunkSize = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.host_block_chunk_size'),
            'host_block_chunk_size',
            BoundedPositiveInt::HOST_BLOCK_CHUNK_SIZE_MAX,
        );

        Passport::client()->newQuery()
            ->where('revoked', false)
            ->chunkById($chunkSize, function (Collection $clients) use ($actor): void {
                /** @var Client $client */
                foreach ($clients as $client) {
                    if ($this->redirectUriGuard->clientHasBlockedRedirectHost($client)) {
                        $this->blockClientAction->execute($client, $actor);
                    }
                }
            });

        return $blockedHost;
    }
}
