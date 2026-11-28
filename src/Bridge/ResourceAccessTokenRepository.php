<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Bridge;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use League\OAuth2\Server\Exception\OAuthServerException;
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

        /** @var Token|null $sourceToken League validated it, but the product can remove it concurrently */
        $sourceToken = Passport::token()->newQuery()->find($tokenId);
        $bindingColumn = GrantBindingColumn::from($this->config);
        $binding = $sourceToken?->getAttribute($bindingColumn);

        if ($sourceToken === null || (! is_string($binding) && ! is_int($binding))) {
            throw OAuthServerException::invalidRefreshToken('Token has been revoked');
        }

        $tokens = Passport::token()->newQuery()
            ->where('client_id', $sourceToken->getAttribute('client_id'))
            ->where('user_id', $sourceToken->getAttribute('user_id'))
            ->where($bindingColumn, $binding)
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
