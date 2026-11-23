<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Log;
use Laravel\Passport\Passport;
use League\OAuth2\Server\CryptTrait;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\RevocationReason;
use Qiick\McpOAuth\Internal\GrantBindingColumn;
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
 * revoked too ({@see RevocationReason::Reuse}). A code that was never consumed
 * has no row, so it revokes nothing, and an older code never touches the
 * grant of a newer consent.
 */
final class RevokeAuthCodeTokensAction
{
    use CryptTrait;

    public function __construct(
        private readonly GrantStore $grantStore,
        private readonly ConfigRepository $config,
        string $tokenEncryptionKey,
    ) {
        $this->setEncryptionKey($tokenEncryptionKey);
    }

    public function execute(string $authCodeId): void
    {
        $exchange = OAuthAuthCodeExchange::query()->find($authCodeId);
        $grant = $exchange === null ? null : $this->grantStore->find($exchange->grant_id);

        if ($grant === null) {
            return;
        }

        $grantAccessTokenIds = Passport::token()->newQuery()
            ->where('client_id', $grant->clientId)
            ->where(GrantBindingColumn::from($this->config), $this->grantStore->bindingKey($grant))
            ->select('id');

        Passport::refreshToken()->newQuery()->whereIn('access_token_id', $grantAccessTokenIds)->update(['revoked' => true]);
        Passport::token()->newQuery()->whereIn('id', $grantAccessTokenIds)->update(['revoked' => true]);
        $this->grantStore->revoke($grant->id, null, RevocationReason::Reuse);

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
