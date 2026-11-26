<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Validator;
use Laravel\Mcp\Server\Http\Controllers\OAuthRegisterController;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Qiick\McpOAuth\ClientMetadataUriGuard;
use Qiick\McpOAuth\Events\McpClientRegistered;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\RedirectUriGuard;

/**
 * Dynamic client registration (RFC 7591 / design §8.1). Extends laravel/mcp's
 * controller so every redirect_uri decision goes through {@see RedirectUriGuard}
 * (B3) before the parent validation and Passport create.
 */
final class RegisterClientController extends OAuthRegisterController
{
    /**
     * The RFC 7591 client fields laravel/mcp does not validate, checked in
     * __invoke and written by persistClientMetadata() in the same request.
     * Reset on every call before the parent runs, so a controller instance
     * the route caches never carries one request's fields into the next.
     *
     * @var array<string, mixed>
     */
    private array $additionalClientFields = [];

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

        foreach (['logo_uri', 'client_uri', 'tos_uri', 'policy_uri'] as $metadataUriField) {
            $metadataUri = $request->input($metadataUriField);

            if ($metadataUri === null || $metadataUri === '') {
                continue;
            }

            // https only: a consent page may show these.
            if (! is_string($metadataUri)
                || ! str_starts_with(strtolower($metadataUri), 'https://')
                || ! $this->clientMetadataUriGuard->isAcceptable($metadataUri)) {
                return response()->json([
                    'error' => 'invalid_client_metadata',
                    'error_description' => $metadataUriField.' is not an allowed URI.',
                ], 400);
            }
        }

        // The URI loop above already refused a non-string URI, and `in`
        // refuses an array, so no `string` rule is needed on those fields.
        $additionalFieldsValidator = Validator::make($request->all(), [
            'application_type' => ['nullable', 'in:web,native'],
            'tos_uri' => ['max:2048'],
            'policy_uri' => ['max:2048'],
            'contacts' => ['nullable', 'list', 'max:10'],
            'contacts.*' => ['required', 'string', 'max:320'],
            'software_id' => ['nullable', 'string', 'max:255'],
            'software_version' => ['nullable', 'string', 'max:255'],
        ]);

        if ($additionalFieldsValidator->fails()) {
            return response()->json([
                'error' => 'invalid_client_metadata',
                'error_description' => $additionalFieldsValidator->errors()->first(),
            ], 400);
        }

        $validatedFields = $additionalFieldsValidator->validated();
        $this->additionalClientFields = [];

        // A field sent as null or empty is a field not sent: neither stored nor echoed.
        foreach (['application_type', 'tos_uri', 'policy_uri', 'contacts', 'software_id', 'software_version'] as $fieldName) {
            if (($validatedFields[$fieldName] ?? '') !== '') {
                $this->additionalClientFields[$fieldName] = $validatedFields[$fieldName];
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

        // laravel/mcp creates the client, then calls persistClientMetadata(), and
        // answers 500 when anything throws: one transaction, so a failure never
        // leaves a client without its metadata row (an unregistered client).
        $passportConnection = Passport::client()->getConnection();
        $passportConnection->beginTransaction();
        $isRegistered = false;

        try {
            $response = parent::__invoke($request);
            $isRegistered = $response->getStatusCode() === 201;
        } finally {
            // Any other answer, or an exception, leaves nothing behind.
            if (! $isRegistered) {
                $passportConnection->rollBack();
            }
        }

        if ($isRegistered) {
            $passportConnection->commit();
            $this->dispatchRegisteredEvent($response);
        }

        return $response;
    }

    /**
     * Records the client in `oauth_client_metadata`: that row is what makes a
     * Passport client an MCP client (BindAccessTokenAction binds only those
     * tokens). `token_endpoint_auth_method` is written explicitly (standards
     * review Resolved #2): laravel/mcp registers public clients only. The
     * client fields (laravel/mcp's `logo_uri` and `client_uri`, and the ones
     * __invoke validated) are kept here, never on Passport's table, and
     * returned in the registration response with `client_id_issued_at`, as
     * RFC 7591 §3.2.1 requires. `application_type` is always stored: when
     * the client sends none it is inferred from the redirect URIs (S7).
     *
     * @param  Client  $client  laravel/mcp passes the Passport client it just created
     * @param  array<string, mixed>  $validated
     * @return array<string, mixed>
     */
    protected function persistClientMetadata(mixed $client, array $validated): array
    {
        $registeredFields = [
            ...array_filter(
                ['logo_uri' => $validated['logo_uri'] ?? null, 'client_uri' => $validated['client_uri'] ?? null],
                static fn (mixed $uri): bool => $uri !== null && $uri !== '',
            ),
            ...$this->additionalClientFields,
        ];

        /** @var list<string> $redirectUris laravel/mcp validated each one as a string */
        $redirectUris = $validated['redirect_uris'];
        $registeredFields['application_type'] ??= $this->inferredApplicationType($redirectUris);
        $issuedAt = now();

        OAuthClientMetadata::query()->create([
            'client_id' => $client->getKey(),
            'registration_source' => 'dcr',
            'token_endpoint_auth_method' => 'none',
            'client_id_issued_at' => $issuedAt,
            ...$registeredFields,
        ]);

        return [...$registeredFields, 'client_id_issued_at' => $issuedAt->getTimestamp()];
    }

    /**
     * `native` when every redirect URI is one a native app receives, `web`
     * otherwise. A client that declares `web` with a loopback redirect is
     * not refused: MCP clients registered that way before the field existed.
     *
     * @param  list<string>  $redirectUris
     */
    private function inferredApplicationType(array $redirectUris): string
    {
        foreach ($redirectUris as $redirectUri) {
            if (! $this->redirectUriGuard->isNativeRedirectUri($redirectUri)) {
                return 'web';
            }
        }

        return 'native';
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

    /**
     * Public DCR bodies stay small: over 65 536 bytes is a 413. A local value,
     * not a class constant: pcov never covers a constant, so mutation could
     * not test the limit.
     */
    private function bodyExceedsLimit(Request $request): bool
    {
        $maxBodyBytes = 65_536;
        $contentLengthHeader = $request->headers->get('Content-Length');

        // Header path and raw-body path both refuse oversize payloads. A digit
        // string compares numerically with an int, so no cast is needed.
        if (is_string($contentLengthHeader) && ctype_digit($contentLengthHeader) && $contentLengthHeader > $maxBodyBytes) {
            return true;
        }

        return strlen($request->getContent()) > $maxBodyBytes;
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
