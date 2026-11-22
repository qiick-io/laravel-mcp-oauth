<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

/**
 * Readiness probe values products plug into their own /up endpoint.
 * Empty while OAuth is off; reports passport_keys only while enabled.
 *
 * @api
 */
final class McpOAuthReadiness
{
    public function __construct(
        private readonly McpOAuthServer $server,
    ) {}

    /**
     * @return array<string, 'ok'|'fail'>
     */
    public function checks(): array
    {
        if (! $this->server->isEnabled()) {
            return [];
        }

        return [
            'passport_keys' => $this->server->hasPassportKeys() ? 'ok' : 'fail',
        ];
    }
}
