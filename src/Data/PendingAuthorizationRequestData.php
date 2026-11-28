<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;

/**
 * The pending authorization request a consent form was posted for, the
 * signed-in user it belongs to, its client re-read as active and unblocked,
 * and what the rendered page showed: the consent text version, the locale
 * and the resource. The decision and its evidence carry those, never values
 * read again on submit.
 *
 * @internal
 */
final readonly class PendingAuthorizationRequestData
{
    /** @param array<string, string> $resourceScopes */
    public function __construct(
        public AuthorizationRequestInterface $authorizationRequest,
        public Client $client,
        public Authenticatable $user,
        public ?string $renderedConsentVersion,
        public string $renderedLocale,
        public string $renderedResource,
        public array $resourceScopes = [],
        public ?GrantInstallationData $installation = null,
    ) {}
}
