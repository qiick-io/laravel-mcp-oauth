<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Passport\Client;
use League\Uri\UriString;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Throwable;

/**
 * Redirect URI and blocked-host rules: League Uri only, ASCII registered hosts,
 * UTS #46 nontransitional STD3 for admin input, exact or subdomain block.
 *
 * @api
 */
final class RedirectUriGuard
{
    public function __construct(
        private readonly BlockedHostCatalog $blockedHosts = new BlockedHostCatalog,
    ) {}

    public function isAcceptableForRegistration(string $redirectUri): bool
    {
        if (str_contains($redirectUri, '#') || str_contains($redirectUri, '\\')) {
            return false;
        }

        try {
            $parts = UriString::parse($redirectUri);
        } catch (Throwable) {
            return false;
        }

        $scheme = $parts['scheme'] ?? null;

        if (! is_string($scheme) || $scheme === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            return false;
        }

        if (in_array(Str::lower($scheme), $this->dangerousSchemes(), true)) {
            return false;
        }

        // League always sets user/pass keys; refuse either when present.
        if (($parts['user'] ?? null) !== null || ($parts['pass'] ?? null) !== null) { // @pest-mutate-ignore: CoalesceRemoveLeft
            return false;
        }

        $rawHost = $parts['host'] ?? null;

        if (! is_string($rawHost) || $rawHost === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            return true;
        }

        // Defense in depth: percent-encoded hosts also fail normalizeHost.
        if (str_contains($rawHost, '%')) {
            return false; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        try {
            $this->assertRedirectHostIsAscii($rawHost);
            $this->normalizeHost($this->unwrapIpv6Host($rawHost));
        } catch (InvalidArgumentException) {
            return false;
        }

        return true;
    }

    public function isAllowedScheme(string $redirectUri): bool
    {
        try {
            $parts = UriString::parse($redirectUri);
        } catch (Throwable) {
            return false;
        }

        $scheme = $parts['scheme'] ?? null;

        if (! is_string($scheme) || $scheme === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanOrToBooleanAnd
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        $normalizedScheme = Str::lower($scheme);

        if (in_array($normalizedScheme, $this->dangerousSchemes(), true)) {
            return false;
        }

        if ($normalizedScheme === 'https') {
            return true;
        }

        if ($normalizedScheme === 'http') {
            $rawHost = $parts['host'] ?? null;

            if (! is_string($rawHost) || $rawHost === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
                return false;
            }

            try {
                $host = $this->normalizeHost($rawHost);
            } catch (InvalidArgumentException) {
                return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
            }

            return in_array($host, $this->loopbackHosts(), true);
        }

        $customSchemes = config('mcp.custom_schemes', []);

        if (! is_array($customSchemes)) {
            return false;
        }

        $allowed = [];

        foreach ($customSchemes as $value) {
            if (is_string($value) && $value !== '') { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanAndToBooleanOr
                $allowed[] = Str::lower($value);
            }
        }

        return in_array($normalizedScheme, $allowed, true);
    }

    /**
     * @throws InvalidArgumentException
     */
    public function normalizeHost(string $host): string
    {
        $normalizedHost = Str::lower(rtrim(trim($this->unwrapIpv6Host($host)), '.'));

        if ($normalizedHost === '') {
            throw new InvalidArgumentException('Host is empty.');
        }

        if (filter_var($normalizedHost, FILTER_VALIDATE_IP) !== false) {
            return $normalizedHost;
        }

        // IDNA_DEFAULT already includes NONTRANSITIONAL_TO_ASCII; OR STD3 so underscores fail.
        $asciiHost = idn_to_ascii(
            $normalizedHost,
            IDNA_DEFAULT | IDNA_USE_STD3_RULES, // @pest-mutate-ignore: BitwiseOrToBitwiseAnd
            INTL_IDNA_VARIANT_UTS46,
        );

        // idn_to_ascii returns false on STD3/IDNA failure; '?' is the legacy soft failure.
        if ($asciiHost === false || $asciiHost === '' || str_contains($asciiHost, '?')) { // @pest-mutate-ignore: EmptyStringToNotEmpty
            throw new InvalidArgumentException('Host is not a valid internationalised domain name.');
        }

        return Str::lower($asciiHost);
    }

    /**
     * @throws InvalidArgumentException
     */
    public function hostOf(string $redirectUri): ?string
    {
        try {
            $parts = UriString::parse($redirectUri);
        } catch (Throwable $exception) {
            throw new InvalidArgumentException('Redirect URI could not be parsed.', 0, $exception); // @pest-mutate-ignore: DecrementInteger,IncrementInteger
        }

        $rawHost = $parts['host'] ?? null;

        if (! is_string($rawHost) || $rawHost === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            return null;
        }

        $this->assertRedirectHostIsAscii($rawHost);

        return $this->normalizeHost($rawHost);
    }

    public function displayHostOf(string $redirectUri): string
    {
        try {
            $parts = UriString::parse($redirectUri);
        } catch (Throwable) {
            return '';
        }

        $scheme = $parts['scheme'] ?? null;
        $normalizedScheme = is_string($scheme) ? Str::lower($scheme) : '';

        // Private-use / custom schemes: show the scheme, never a path-looking host.
        if ($normalizedScheme !== '' && ! in_array($normalizedScheme, ['https', 'http'], true)) { // @pest-mutate-ignore: EmptyStringToNotEmpty
            return $normalizedScheme;
        }

        $rawHost = $parts['host'] ?? null;

        if (is_string($rawHost) && $rawHost !== '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            try {
                return $this->normalizeHost($rawHost);
            } catch (InvalidArgumentException) {
                return $this->unwrapIpv6Host($rawHost);
            }
        }

        return $normalizedScheme;
    }

    public function isHostBlocked(string $host): bool
    {
        try {
            $normalizedHost = $this->normalizeHost($host);
        } catch (InvalidArgumentException) {
            return true;
        }

        foreach ($this->blockedHosts->all() as $blockedHost) {
            if ($blockedHost === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
                continue;
            }

            try {
                $normalizedBlocked = $this->normalizeHost($blockedHost);
            } catch (InvalidArgumentException) {
                continue;
            }

            if ($normalizedHost === $normalizedBlocked) {
                return true;
            }

            if (str_ends_with($normalizedHost, '.'.$normalizedBlocked)) {
                return true;
            }
        }

        return false;
    }

    public function clientHasBlockedRedirectHost(Client $client): bool
    {
        $redirectUris = $client->getAttribute('redirect_uris');

        // Passport's redirectUris Attribute always returns an array; keep the guard for stubs.
        if (! is_array($redirectUris)) {
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        foreach ($redirectUris as $redirectUri) {
            if (! is_string($redirectUri)) {
                continue;
            }

            try {
                $host = $this->hostOf($redirectUri);
            } catch (InvalidArgumentException) {
                return true;
            }

            if ($host !== null && $this->isHostBlocked($host)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function assertRedirectHostIsAscii(string $host): void
    {
        $candidate = $this->unwrapIpv6Host($host);

        if (preg_match('/[^\x00-\x7F]/', $candidate) === 1) {
            throw new InvalidArgumentException('Redirect host must be ASCII; register the punycode form for an IDN.');
        }
    }

    private function unwrapIpv6Host(string $host): string
    {
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) { // @pest-mutate-ignore: BooleanAndToBooleanOr
            return substr($host, 1, -1);
        }

        return $host;
    }

    /**
     * @return list<string>
     */
    private function dangerousSchemes(): array
    {
        return [
            'javascript',
            'data',
            'vbscript',
            'file',
        ];
    }

    /**
     * @return list<string>
     */
    private function loopbackHosts(): array
    {
        return [
            '127.0.0.1',
            'localhost',
            '::1',
        ];
    }
}
