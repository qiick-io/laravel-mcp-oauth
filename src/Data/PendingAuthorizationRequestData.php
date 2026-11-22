<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

/**
 * The pending authorization request a consent form was posted for, the
 * signed-in user it belongs to, and its client re-read as active and
 * unblocked.
 *
 * @internal
 */
final readonly class PendingAuthorizationRequestData
{
    public function __construct(
        public AuthorizationRequestInterface $authorizationRequest,
        public Client $client,
        public Authenticatable $user,
    ) {}
}
