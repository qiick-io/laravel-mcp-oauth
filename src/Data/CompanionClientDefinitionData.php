<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use InvalidArgumentException;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Shipped metadata for a first-party Companion build. Its client identifier
 * is a CIMD URL and its callbacks are app-claimed HTTPS URIs.
 *
 * @api
 */
final readonly class CompanionClientDefinitionData
{
    /**
     * @param  non-empty-list<string>  $redirectUris
     *
     * @throws InvalidArgumentException when the shipped definition is invalid
     */
    public function __construct(
        public string $identifier,
        public string $name,
        public array $redirectUris,
        public string $operatorName,
    ) {
        $uriGuard = new RedirectUriGuard;

        if ($uriGuard->parseClientIdentifierUrl($identifier) === null) {
            throw new InvalidArgumentException('Companion client requires an HTTPS client identifier URL with a path.');
        }

        if (trim($name) === '' || strlen($name) > 255 || trim($operatorName) === '') {
            throw new InvalidArgumentException('Companion client requires a name and an operator.');
        }

        if ($redirectUris === [] || ! array_is_list($redirectUris)) {
            throw new InvalidArgumentException('Companion client requires a list of HTTPS callback URIs.');
        }

        foreach ($redirectUris as $redirectUri) {
            if (! is_string($redirectUri) || strlen($redirectUri) > 1024 || ! $uriGuard->isAcceptableForRegistration($redirectUri)
                || $uriGuard->parseCanonical($redirectUri)->scheme !== 'https') {
                throw new InvalidArgumentException('Companion client requires exact HTTPS callback URIs.');
            }
        }
    }
}
