<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * Use-time entitlement result. The package alone renders RFC 6750 from this.
 *
 * @api
 */
final readonly class AuthorizationDecision
{
    private function __construct(
        public bool $isAllowed,
        public ?string $error,
        public ?string $description,
        public ?string $scope,
    ) {}

    public static function allow(): self
    {
        return new self(true, null, null, null);
    }

    public static function invalidToken(string $description): self
    {
        return new self(false, 'invalid_token', $description, null);
    }

    public static function insufficientScope(string $scope, string $description): self
    {
        return new self(false, 'insufficient_scope', $description, $scope);
    }
}
