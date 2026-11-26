<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\Contracts\AuditLogger;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Events\McpClientBlocked;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\Models\OAuthClientMetadata;

/**
 * An admin blocks a client (design §8.2): in one transaction the client is
 * revoked, its metadata row marked (`revocation_reason = admin`, which
 * starts the retention clock), every grant it holds revoked through the
 * product's GrantStore, and every access token, refresh token and auth code
 * it holds revoked. The next consent, token request and `/mcp` call fail.
 *
 * Dispatches {@see McpClientBlocked} after the commit.
 */
final class BlockClientAction
{
    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly AuditLogger $auditLogger,
    ) {}

    public function execute(Client $client, ?Authenticatable $actor): void
    {
        /** @var string $clientId Passport client ids are UUID strings */
        $clientId = $client->getKey();
        $actorIdentifier = $actor === null ? null : PassportUserIdentifier::of($actor);

        $client->getConnection()->transaction(function () use ($client, $clientId, $actor, $actorIdentifier): void {
            $client->forceFill(['revoked' => true])->save();

            OAuthClientMetadata::query()
                ->where('client_id', $clientId)
                ->whereNull('revoked_at')
                ->update(['revoked_at' => now(), 'revocation_reason' => 'admin']);

            Passport::refreshToken()->newQuery()
                ->whereIn('access_token_id', Passport::token()->newQuery()->select('id')->where('client_id', $clientId))
                ->update(['revoked' => true]);
            Passport::token()->newQuery()->where('client_id', $clientId)->update(['revoked' => true]);
            Passport::authCode()->newQuery()->where('client_id', $clientId)->update(['revoked' => true]);

            $this->grantStore->revokeAllForClient($clientId, $actorIdentifier);
            $this->auditLogger->record('oauth_client_blocked', $actor, null, ['client_id' => $clientId]);
        });

        event(new McpClientBlocked($clientId, $actorIdentifier));
    }
}
