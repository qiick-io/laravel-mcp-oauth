<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Illuminate\Http\Request;
use Qiick\McpOAuth\Contracts\ApiKeyDoor;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * In-memory {@see ApiKeyDoor} for package tests and product fakes: a key has
 * the shape `ak_…`, and only the keys it was given authenticate. A forbidden
 * key is the product's 403, any other key its 401.
 *
 * @api
 */
final class FakeApiKeyDoor implements ApiKeyDoor
{
    /** @var list<string> the bearers authenticate() was asked about, oldest first */
    public array $authenticatedBearers = [];

    /**
     * @param  list<string>  $validApiKeys
     * @param  list<string>  $forbiddenApiKeys  known keys the product refuses with 403
     */
    public function __construct(
        private readonly array $validApiKeys = [],
        private readonly array $forbiddenApiKeys = [],
    ) {}

    public function isApiKeyShaped(string $bearer): bool
    {
        return str_starts_with($bearer, 'ak_');
    }

    public function authenticate(Request $request, string $bearer): object
    {
        $this->authenticatedBearers[] = $bearer;

        if (in_array($bearer, $this->forbiddenApiKeys, true)) {
            throw new HttpException(403, 'This API key may not use MCP.');
        }

        if (! in_array($bearer, $this->validApiKeys, true)) {
            throw new HttpException(401, 'Unknown API key.');
        }

        return (object) ['apiKey' => $bearer];
    }
}
