<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use InvalidArgumentException;

/**
 * A product audience and its sole wire scope. Only clients classified by
 * the server in the allowed classes can request the resource.
 *
 * @api
 */
final readonly class ProtectedResourceDefinitionData
{
    /** @param non-empty-list<string> $allowedClientClasses server-assigned registration classes */
    public function __construct(
        public string $identifier,
        public string $scope,
        public array $allowedClientClasses,
    ) {
        // OAuth scopes are single ASCII tokens (RFC 6749 §3.3).
        if (preg_match('/\A[\x21\x23-\x5B\x5D-\x7E]+\z/', $scope) !== 1 || strlen($scope) > 255) {
            throw new InvalidArgumentException('A protected resource needs one OAuth scope.');
        }

        if ($allowedClientClasses === [] || ! array_is_list($allowedClientClasses)) {
            throw new InvalidArgumentException('A protected resource needs one or more allowed client classes.');
        }

        foreach ($allowedClientClasses as $clientClass) {
            if (! is_string($clientClass) || preg_match('/\A[a-z][a-z0-9_]{0,15}\z/', $clientClass) !== 1) {
                throw new InvalidArgumentException('A protected resource client class must be a registration class.');
            }
        }
    }
}
