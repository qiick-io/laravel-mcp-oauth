<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Laravel\Mcp\Server\Http\Controllers\OAuthRegisterController;
use Laravel\Passport\Passport;
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
    /**
     * Public DCR bodies stay small; larger payloads are refused with 413.
     * pcov never covers a constant declaration, so mutation cannot run tests
     * against it; the boundary tests pin 65 536 as a literal instead.
     */
    public const int MAX_BODY_BYTES = 65_536; // @pest-mutate-ignore: DecrementInteger,IncrementInteger

    public function __construct(
        private readonly RedirectUriGuard $redirectUriGuard,
        private readonly ClientMetadataUriGuard $clientMetadataUriGuard,
        private readonly ConfigRepository $config,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        if ($this->bodyExceedsLimit($request)) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => 'The request body exceeds the registration size limit.',
            ], 413);
        }

        $redirectUris = $request->input('redirect_uris');

        if ($redirectUris !== null && (! is_array($redirectUris) || ! array_is_list($redirectUris))) {
            return response()->json([
                'error' => 'invalid_redirect_uri',
                'error_description' => 'redirect_uris must be a JSON array.',
            ], 400);
        }

        if ($this->clientNameContainsDisallowedCharacters($request)) {
            return response()->json([
                'error' => 'invalid_client_metadata',
                'error_description' => 'client_name must be valid UTF-8 with visible text and no control, separator or formatting characters.',
            ], 400);
        }

        foreach (['logo_uri', 'client_uri'] as $metadataUriField) {
            $metadataUri = $request->input($metadataUriField);

            if ($metadataUri === null || $metadataUri === '') {
                continue;
            }

            if (! is_string($metadataUri) || ! $this->clientMetadataUriGuard->isAcceptable($metadataUri)) {
                return response()->json([
                    'error' => 'invalid_client_metadata',
                    'error_description' => $metadataUriField.' is not an allowed URI.',
                ], 400);
            }
        }

        foreach ($this->stringRedirectUris($redirectUris) as $redirectUri) {
            if (! $this->isRedirectUriAllowedForRegistration($redirectUri)) {
                return response()->json([
                    'error' => 'invalid_redirect_uri',
                    'error_description' => 'One or more redirect_uris are not allowed.',
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
                'error' => 'temporarily_unavailable',
                'error_description' => 'The global OAuth client registration cap has been reached.',
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

        $firstRedirectUri = Arr::get($validated, 'redirect_uris.0');

        if (! is_string($firstRedirectUri)) {
            return 'MCP Client';
        }

        $displayHost = $this->redirectUriGuard->displayHostOf($firstRedirectUri);

        return $displayHost !== '' ? $displayHost : 'MCP Client';
    }

    private function bodyExceedsLimit(Request $request): bool
    {
        $contentLengthHeader = $request->headers->get('Content-Length');

        // Header path and raw-body path both refuse oversize payloads. A digit
        // string compares numerically with an int, so no cast is needed.
        if (is_string($contentLengthHeader) && ctype_digit($contentLengthHeader) && $contentLengthHeader > self::MAX_BODY_BYTES) {
            return true;
        }

        return strlen($request->getContent()) > self::MAX_BODY_BYTES;
    }

    /**
     * The client name is shown on the consent screen as the client's own
     * claim, so nothing in it may reorder, hide or break the text around it.
     * Fails closed: invalid UTF-8 (reachable through a form-encoded body)
     * makes the `/u` pattern fail, and any PCRE error counts as disallowed.
     */
    private function clientNameContainsDisallowedCharacters(Request $request): bool
    {
        // resolveClientName() falls back to `name`, so both keys are checked.
        foreach (['client_name', 'name'] as $nameKey) {
            $nameValue = $request->input($nameKey);

            if (! is_string($nameValue) || $nameValue === '') {
                continue;
            }

            // Refused: C0/C1 controls (Cc), line and paragraph separators
            // (Zl, Zp), Hangul fillers (blank letters, class Lo) and format
            // characters (Cf) except ZWNJ (U+200C, Persian) and ZWJ (U+200D,
            // emoji sequences). preg_match false (an error) is not 0: refused.
            if (preg_match('/[\p{Cc}\p{Zl}\p{Zp}\x{115F}\x{1160}\x{3164}\x{FFA0}]|(?![\x{200C}\x{200D}])\p{Cf}/u', $nameValue) !== 0) {
                return true;
            }

            // A name made only of spaces, combining marks (variation
            // selectors, CGJ included), joiners or the blank braille pattern
            // would render as nothing next to "wants access".
            if (preg_match('/[^\p{Z}\p{M}\x{200C}\x{200D}\x{2800}]/u', $nameValue) !== 1) {
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
        // data_get reads the decoded object the same way it reads an array.
        $payload = $response->getData();
        $clientId = data_get($payload, 'client_id');
        $registeredRedirectUris = data_get($payload, 'redirect_uris');

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

    /**
     * Counts on Passport's configured client model, the one its
     * ClientRepository writes to: a product that calls
     * `Passport::useClientModel()` must not leave the cap counting a table
     * nobody fills.
     */
    private function nonRevokedClientCount(): int
    {
        return Passport::client()->newQuery()->where('revoked', false)->count();
    }
}
