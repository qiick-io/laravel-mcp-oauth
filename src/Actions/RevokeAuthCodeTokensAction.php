<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Support\Facades\Log;
use League\OAuth2\Server\CryptTrait;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;

/**
 * An authorization code came back after it was consumed: revoke every token
 * issued with it (RFC 6749 §4.1.2, RFC 9700 §4.5), because a second
 * presentation means the code leaked.
 *
 * The tokens issued with a code are the tokens bound to the grant it was
 * consumed under ({@see OAuthAuthCodeExchange}), refreshed ones included:
 * every approval revokes the earlier codes and tokens of that client and
 * user, so a grant only ever carries the tokens of its own code. The grant is
 * revoked first ({@see RevocationReason::Reuse}), then its tokens; a grant
 * that is already revoked is left as it is. A code that was never consumed
 * has no row, so it revokes nothing, and an older code never touches the
 * grant of a newer consent.
 *
 * @internal
 */
final class RevokeAuthCodeTokensAction
{
    use CryptTrait;

    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly RevokeGrantTokensAction $revokeGrantTokens,
        string $tokenEncryptionKey,
    ) {
        $this->setEncryptionKey($tokenEncryptionKey);
    }

    public function execute(string $authCodeId): void
    {
        $exchange = OAuthAuthCodeExchange::query()->find($authCodeId);
        $grant = $exchange === null || $exchange->expires_at !== null ? null : $this->grantStore->find($exchange->grant_id);

        // Already revoked: its tokens are refused at use, and the first reason stays.
        if ($grant === null || $grant->revoked) {
            return;
        }

        // The grant first: a race winner still binding its token then finds it
        // revoked and revokes that token itself (BindAccessTokenAction).
        $this->grantStore->revoke($grant->id, null, RevocationReason::Reuse);

        $this->revokeGrantTokens->execute($grant);

        Log::warning('MCP OAuth authorization code presented again: its tokens and grant are revoked.', [
            'client_id' => $grant->clientId,
            'grant_id' => $grant->id,
        ]);
    }

    /**
     * League checks expiry before it asks whether a code was used, so a code
     * replayed after it expired never reaches OneShotAuthCodeRepository. The
     * token endpoint passes such a code here, after league has decrypted it
     * and found it expired; it is decrypted again with the same key.
     */
    public function executeForExpiredCode(string $encryptedAuthCode): void
    {
        /** @var array{auth_code_id?: mixed} $payload league's own payload */
        $payload = json_decode($this->decrypt($encryptedAuthCode), true);
        $authCodeId = $payload['auth_code_id'] ?? null;

        if (is_string($authCodeId)) {
            $this->execute($authCodeId);
        }
    }
}
