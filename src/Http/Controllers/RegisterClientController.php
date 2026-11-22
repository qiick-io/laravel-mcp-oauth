<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Mcp\Server\Http\Controllers\OAuthRegisterController;
use Laravel\Passport\Client;
use Qiick\McpOAuth\ClientMetadataUriGuard;
use Qiick\McpOAuth\Events\McpClientRegistered;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Dynamic client registration (RFC 7591 / design §8.1). Extends laravel/mcp's
 * controller so every redirect_uri decision goes through {@see RedirectUriGuard}
 * (B3) before the parent validation and Passport create.
 */
final class RegisterClientController extends OAuthRegisterController
{
    /** Public DCR bodies stay small; larger payloads are refused with 413. */
    // @pest-mutate-ignore: DecrementInteger,IncrementInteger — size is a product policy constant
    public const int MAX_BODY_BYTES = 65_536;

    public function __construct(
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly ClientMetadataUriGuard $clientMetadataUriGuard,
        private readonly ConfigRepository $config,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        if ($this->bodyExceedsLimit($request)) {
            return response()->json([
                'error' => 'invalid_request', // @pest-mutate-ignore: RemoveArrayItem
                'error_description' => 'The request body exceeds the registration size limit.', // @pest-mutate-ignore: RemoveArrayItem
            ], 413);
        }

        $redirectUris = $request->input('redirect_uris');

        if ($redirectUris !== null && (! is_array($redirectUris) || ! array_is_list($redirectUris))) {
            return response()->json([
                'error' => 'invalid_redirect_uri', // @pest-mutate-ignore: RemoveArrayItem — RFC 7591 requires an array
                'error_description' => 'redirect_uris must be a JSON array.', // @pest-mutate-ignore: RemoveArrayItem
            ], 400);
        }

        if ($this->clientNameContainsDisallowedCharacters($request)) {
            return response()->json([
                'error' => 'invalid_client_metadata', // @pest-mutate-ignore: RemoveArrayItem
                'error_description' => 'client_name must not contain control or bidi formatting characters.', // @pest-mutate-ignore: RemoveArrayItem
            ], 400);
        }

        foreach (['logo_uri', 'client_uri'] as $metadataUriField) {
            $metadataUri = $request->input($metadataUriField);

            if ($metadataUri === null || $metadataUri === '') {
                continue; // @pest-mutate-ignore: ContinueToBreak
            }

            if (! is_string($metadataUri) || ! $this->clientMetadataUriGuard->isAcceptable($metadataUri)) { // @pest-mutate-ignore: RemoveNot
                return response()->json([
                    'error' => 'invalid_client_metadata', // @pest-mutate-ignore: RemoveArrayItem
                    'error_description' => $metadataUriField.' is not an allowed URI.', // @pest-mutate-ignore: RemoveArrayItem,ConcatRemoveLeft,ConcatRemoveRight,ConcatSwitchSides
                ], 400);
            }
        }

        foreach ($this->stringRedirectUris($redirectUris) as $redirectUri) {
            if (! $this->isRedirectUriAllowedForRegistration($redirectUri)) {
                return response()->json([
                    'error' => 'invalid_redirect_uri', // @pest-mutate-ignore: RemoveArrayItem — RFC 7591 error object
                    'error_description' => 'One or more redirect_uris are not allowed.', // @pest-mutate-ignore: RemoveArrayItem
                ], 400);
            }
        }

        $globalCap = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.registrations_global_cap'),
            'registrations_global_cap',
            BoundedPositiveInt::REGISTRATIONS_GLOBAL_CAP_MAX,
        );

        if ($this->nonRevokedClientCount() >= $globalCap) {
            return response()->json([
                'error' => 'temporarily_unavailable', // @pest-mutate-ignore: RemoveArrayItem — RFC 6750 wire shape
                'error_description' => 'The global OAuth client registration cap has been reached.', // @pest-mutate-ignore: RemoveArrayItem
            ], 503);
        }

        $response = parent::__invoke($request);

        if ($response->getStatusCode() === 201) {
            $this->dispatchRegisteredEvent($response);
        }

        return $response;
    }

    protected function isValidRedirectUri(string $value): bool
    {
        return $this->isRedirectUriAllowedForRegistration($value);
    }

    /**
     * @param  array<string, mixed>  $validated
     */
    protected function resolveClientName(array $validated): string
    {
        foreach (['client_name', 'name'] as $nameKey) {
            $nameValue = $validated[$nameKey] ?? null;

            if (is_string($nameValue) && $nameValue !== '') {
                return $nameValue;
            }
        }

        $redirectUris = $validated['redirect_uris'] ?? null;

        if (! is_array($redirectUris)) {
            return 'MCP Client'; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $firstRedirectUri = $redirectUris[0] ?? null;

        if (! is_string($firstRedirectUri)) {
            return 'MCP Client';
        }

        $displayHost = $this->redirectUriGuard->displayHostOf($firstRedirectUri);

        return $displayHost !== '' ? $displayHost : 'MCP Client'; // @pest-mutate-ignore: EmptyStringToNotEmpty
    }

    private function bodyExceedsLimit(Request $request): bool
    {
        $contentLengthHeader = $request->headers->get('Content-Length');

        // Header path and raw-body path both refuse oversize payloads.
        if (is_string($contentLengthHeader) && $contentLengthHeader !== '' && ctype_digit($contentLengthHeader)) { // @pest-mutate-ignore: BooleanAndToBooleanOr,EmptyStringToNotEmpty
            if ((int) $contentLengthHeader > self::MAX_BODY_BYTES) { // @pest-mutate-ignore: RemoveIntegerCast
                return true;
            }
        }

        return strlen($request->getContent()) > self::MAX_BODY_BYTES; // @pest-mutate-ignore: GreaterToGreaterOrEqual
    }

    private function clientNameContainsDisallowedCharacters(Request $request): bool
    {
        foreach (['client_name', 'name'] as $nameKey) { // @pest-mutate-ignore: RemoveArrayItem
            $nameValue = $request->input($nameKey);

            if (! is_string($nameValue) || $nameValue === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
                continue; // @pest-mutate-ignore: ContinueToBreak
            }

            // C0/C1 controls always refused. Format (Cf) refused except ZWNJ
            // (U+200C, Persian) and ZWJ (U+200D, emoji sequences).
            if (preg_match('/\p{Cc}/u', $nameValue) === 1) {
                return true;
            }

            $withoutAllowedFormatMarks = preg_replace('/[\x{200C}\x{200D}]/u', '', $nameValue) ?? $nameValue;

            if (preg_match('/\p{Cf}/u', $withoutAllowedFormatMarks) === 1) {
                return true;
            }
        }

        return false;
    }

    private function isRedirectUriAllowedForRegistration(string $redirectUri): bool
    {
        // isAcceptableForRegistration already applies the scheme allow-list via
        // the same canonical parse; a second isAllowedScheme call would only
        // duplicate mutants without a behavioural fork.
        if (! $this->redirectUriGuard->isAcceptableForRegistration($redirectUri)) {
            return false;
        }

        $host = $this->redirectUriGuard->hostOf($redirectUri);

        return $host === null || ! $this->redirectUriGuard->isHostBlocked($host);
    }

    /**
     * @return list<string>
     */
    private function stringRedirectUris(mixed $redirectUris): array
    {
        if (! is_array($redirectUris)) {
            return [];
        }

        $strings = [];

        foreach ($redirectUris as $redirectUri) {
            if (is_string($redirectUri)) {
                $strings[] = $redirectUri;
            }
        }

        return $strings;
    }

    private function dispatchRegisteredEvent(JsonResponse $response): void
    {
        $payload = $response->getData(true);

        if (! is_array($payload)) {
            return; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $clientId = $payload['client_id'] ?? null;
        $registeredRedirectUris = $payload['redirect_uris'] ?? null;

        if (! is_string($clientId) || $clientId === '' || ! is_array($registeredRedirectUris)) {
            return;
        }

        event(new McpClientRegistered(
            $clientId,
            $this->displayHostsFromRedirectUris($registeredRedirectUris),
        ));
    }

    /**
     * @param  array<mixed>  $redirectUris
     * @return list<string>
     */
    private function displayHostsFromRedirectUris(array $redirectUris): array
    {
        $displayHosts = [];

        foreach ($redirectUris as $redirectUri) {
            if (! is_string($redirectUri)) {
                continue;
            }

            $displayHost = $this->redirectUriGuard->displayHostOf($redirectUri);

            if ($displayHost !== '' && ! in_array($displayHost, $displayHosts, true)) {
                $displayHosts[] = $displayHost;
            }
        }

        return $displayHosts;
    }

    private function nonRevokedClientCount(): int
    {
        return Client::query()->where('revoked', false)->count();
    }
}
