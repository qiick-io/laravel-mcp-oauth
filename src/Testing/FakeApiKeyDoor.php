<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Testing;

use Illuminate\Http\Request;
use Qiick\McpOAuth\Contracts\ApiKeyDoor;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * In-memory {@see ApiKeyDoor} for package tests and product fakes: a key has
 * the shape `ak_…`, and only the keys it was given authenticate. Any other
 * key is the product's 401.
 *
 * @api
 */
final class FakeApiKeyDoor implements ApiKeyDoor
{
    /** @var list<string> the bearers authenticate() was asked about, oldest first */
    public array $authenticatedBearers = [];

    /**
     * @param  list<string>  $validApiKeys
     */
    public function __construct(
        private readonly array $validApiKeys = [],
    ) {}

    public function isApiKeyShaped(string $bearer): bool
    {
        return str_starts_with($bearer, 'ak_');
    }

    public function authenticate(Request $request, string $bearer): object
    {
        $this->authenticatedBearers[] = $bearer;

        if (! in_array($bearer, $this->validApiKeys, true)) {
            throw new HttpException(401, 'Unknown API key.');
        }

        return (object) ['apiKey' => $bearer];
    }
}
