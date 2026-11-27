<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Qiick\McpOAuth\Data\TokenResourceSelectionData;
use Qiick\McpOAuth\Internal\GrantBindingColumn;

/**
 * League asks to retire the refresh's source access token. Retire this
 * grant's tokens for the selected audience instead so another audience
 * stays usable. The family repository still revokes every audience on reuse.
 *
 * @internal
 */
final class ResourceAccessTokenRepository extends AccessTokenRepository
{
    public function __construct(Dispatcher $events, private readonly ConfigRepository $config)
    {
        parent::__construct($events);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $selection = TokenResourceSelectionData::from(request());

        if ($selection?->grantId === null) {
            parent::revokeAccessToken($tokenId);

            return;
        }

        /** @var Token $sourceToken League already validated it when loading the refresh */
        $sourceToken = Passport::token()->newQuery()->findOrFail($tokenId);
        $bindingColumn = GrantBindingColumn::from($this->config);
        $tokens = Passport::token()->newQuery()
            ->where('client_id', $sourceToken->getAttribute('client_id'))
            ->where('user_id', $sourceToken->getAttribute('user_id'))
            ->where($bindingColumn, $sourceToken->getAttribute($bindingColumn))
            ->where('audience', $selection->identifier)
            ->where('revoked', false)
            ->get(['id', 'audience']);

        foreach ($tokens as $token) {
            // The audience comparison is case-sensitive on every supported database.
            $identifier = $token->getKey();

            if (is_string($identifier) && $token->getAttribute('audience') === $selection->identifier) {
                parent::revokeAccessToken($identifier);
            }
        }
    }
}
