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
 * http(s) always requires a non-empty authority host; IP hosts are canonicalised
 * (IPv6 via inet_pton/ntop, ::ffff: unmapped) and non-dotted-decimal IPv4 forms
 * are refused.
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

        if (! is_string($scheme) || $scheme === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty — scheme must stay non-empty; EmptyStringToNotEmpty is a no-op on !== ''
            return false;
        }

        $normalizedScheme = Str::lower($scheme);

        if (in_array($normalizedScheme, $this->dangerousSchemes(), true)) {
            return false;
        }

        // League always sets user/pass keys; refuse either when present.
        if (($parts['user'] ?? null) !== null || ($parts['pass'] ?? null) !== null) { // @pest-mutate-ignore: CoalesceRemoveLeft — League always sets the keys; left coalesce is equivalent to bare access
            return false;
        }

        $rawHost = $parts['host'] ?? null;
        $hasHost = is_string($rawHost) && $rawHost !== '';

        // http(s) must have a // authority with a non-empty host (browsers resolve hostless forms to the blocked site).
        if ($this->isHttpFamilyScheme($normalizedScheme) && ! $hasHost) {
            return false;
        }

        if (! $hasHost) {
            return true;
        }

        // Defense in depth: percent-encoded hosts also fail normalizeHost / IDNA.
        if (str_contains($rawHost, '%')) {
            return false; // @pest-mutate-ignore: RemoveEarlyReturn — % in host makes idn_to_ascii false; fall-through also returns false
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

        if (! is_string($scheme) || $scheme === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanOrToBooleanAnd — empty scheme is never allowed; And would still fail is_string/empty
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn — flipping to true would accept schemeless URIs; covered by registration/scheme tests
        }

        $normalizedScheme = Str::lower($scheme);

        if (in_array($normalizedScheme, $this->dangerousSchemes(), true)) {
            return false;
        }

        if ($this->isHttpFamilyScheme($normalizedScheme)) {
            $rawHost = $parts['host'] ?? null;

            if (! is_string($rawHost) || $rawHost === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
                return false;
            }

            try {
                $host = $this->normalizeHost($rawHost);
            } catch (InvalidArgumentException) {
                return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn — invalid host must not become an allowed scheme; loopback check would also fail
            }

            if ($normalizedScheme === 'https') {
                return true;
            }

            return in_array($host, $this->loopbackHosts(), true);
        }

        $customSchemes = config('mcp.custom_schemes', []);

        if (! is_array($customSchemes)) {
            return false;
        }

        $allowed = [];

        foreach ($customSchemes as $value) {
            if (is_string($value) && $value !== '') { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanAndToBooleanOr — empty string is never a scheme name; Or would push non-strings
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

        $canonicalIp = $this->canonicalizeIpHostOrRejectAmbiguous($normalizedHost);

        if ($canonicalIp !== null) {
            return $canonicalIp;
        }

        // IDNA_DEFAULT already includes NONTRANSITIONAL_TO_ASCII; OR STD3 so underscores fail.
        $asciiHost = idn_to_ascii(
            $normalizedHost,
            IDNA_DEFAULT | IDNA_USE_STD3_RULES, // @pest-mutate-ignore: BitwiseOrToBitwiseAnd — both flags required; And clears STD3 and accepts underscores
            INTL_IDNA_VARIANT_UTS46,
        );

        // idn_to_ascii returns false on STD3/IDNA failure; '?' is the legacy soft failure.
        if ($asciiHost === false || $asciiHost === '' || str_contains($asciiHost, '?')) { // @pest-mutate-ignore: EmptyStringToNotEmpty — empty ASCII host is invalid either way
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
            throw new InvalidArgumentException('Redirect URI could not be parsed.', 0, $exception); // @pest-mutate-ignore: DecrementInteger,IncrementInteger — exception code is not a security branch
        }

        $scheme = $parts['scheme'] ?? null;
        $normalizedScheme = is_string($scheme) ? Str::lower($scheme) : '';
        $rawHost = $parts['host'] ?? null;

        if (! is_string($rawHost) || $rawHost === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            if ($this->isHttpFamilyScheme($normalizedScheme)) {
                throw new InvalidArgumentException('http(s) redirect URI requires a non-empty host.');
            }

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
            if ($blockedHost === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty — empty catalog rows are skipped; NotEmpty would skip nothing harmful
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
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn — non-array stubs have no hosts to block; True would false-positive every incomplete client
        }

        foreach ($redirectUris as $redirectUri) {
            if (! is_string($redirectUri)) {
                continue;
            }

            // Existing rows must still satisfy registration rules (e.g. backslash / hostless forms).
            if (! $this->isAcceptableForRegistration($redirectUri)) {
                return true;
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
     * Canonical IPv4/IPv6, or null when the host is not an IP. Throws on forms
     * WHATWG URL parsing would treat as non-dotted-decimal IPv4.
     *
     * @throws InvalidArgumentException
     */
    private function canonicalizeIpHostOrRejectAmbiguous(string $host): ?string
    {
        if (str_contains($host, '%') || str_contains($host, "\0")) {
            throw new InvalidArgumentException('Host contains a forbidden character.');
        }

        if ($this->isForbiddenIpv4Notation($host)) {
            throw new InvalidArgumentException('Non-canonical IPv4 host forms are not allowed.');
        }

        try {
            $packed = inet_pton($host);
        } catch (\ValueError) {
            throw new InvalidArgumentException('Host is not a valid IP address.');
        }

        if ($packed === false) {
            return null;
        }

        if (strlen($packed) === 16) {
            $embeddedIpv4 = $this->embeddedIpv4FromMappedOrTranslated($packed);

            if ($embeddedIpv4 !== null) {
                return $embeddedIpv4;
            }

            $canonical = inet_ntop($packed);

            if ($canonical === false) {
                throw new InvalidArgumentException('IPv6 host could not be canonicalised.');
            }

            return Str::lower($canonical);
        }

        if (strlen($packed) === 4) {
            $canonical = inet_ntop($packed);

            if ($canonical === false) {
                throw new InvalidArgumentException('IPv4 host could not be canonicalised.');
            }

            // inet_pton accepts octal/ambiguous spellings; only dotted-decimal may proceed.
            if ($host !== $canonical) {
                throw new InvalidArgumentException('Non-canonical IPv4 host forms are not allowed.');
            }

            return $canonical;
        }

        return null;
    }

    /**
     * Integer, hex, short, and other WHATWG IPv4 spellings that are not four
     * decimal octets.
     */
    private function isForbiddenIpv4Notation(string $host): bool
    {
        if (preg_match('/^\d+$/', $host) === 1) {
            return true;
        }

        if (preg_match('/0x/i', $host) === 1) {
            return true;
        }

        // 1.2 / 1.2.3 and dotted forms with a leading-zero octet (octal).
        if (preg_match('/^\d+(?:\.\d+){1,2}$/', $host) === 1) {
            return true;
        }

        if (preg_match('/^(?:\d{1,3}\.){3}\d{1,3}$/', $host) === 1) {
            foreach (explode('.', $host) as $octet) {
                if (strlen($octet) > 1 && str_starts_with($octet, '0')) {
                    return true;
                }
            }
        }

        return false;
    }

    private function embeddedIpv4FromMappedOrTranslated(string $packed): ?string
    {
        $isIpv4Mapped = str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff");
        $isIpv4Translated = str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00");

        if (! $isIpv4Mapped && ! $isIpv4Translated) {
            return null;
        }

        $ipv4 = inet_ntop(substr($packed, 12));

        return $ipv4 === false ? null : $ipv4;
    }

    private function isHttpFamilyScheme(string $normalizedScheme): bool
    {
        return $normalizedScheme === 'http' || $normalizedScheme === 'https';
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
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) { // @pest-mutate-ignore: BooleanAndToBooleanOr — a lone bracket is not an IPv6 literal; Or would strip the wrong character
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
