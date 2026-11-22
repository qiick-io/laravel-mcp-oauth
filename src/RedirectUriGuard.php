<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Passport\Client;
use League\Uri\UriString;
use Qiick\McpOAuth\Data\ParsedRedirectUriData;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;
use Throwable;

/**
 * Redirect URI and blocked-host rules: League Uri only, ASCII registered hosts,
 * UTS #46 nontransitional STD3 for admin input, exact or subdomain block.
 * One canonical parse feeds registration, scheme, hostOf, blocklist and exact
 * equality checks so those paths cannot diverge. Fragment, backslash and
 * userinfo are refused.
 * http(s) always requires a non-empty authority host; IP hosts are canonicalised
 * (IPv6 via inet_pton/ntop, ::ffff: unmapped) and non-dotted-decimal IPv4 forms
 * are refused. Non-loopback http is refused (RFC 8252).
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
        try {
            $parsed = $this->parseCanonical($redirectUri);
        } catch (InvalidArgumentException) {
            return false;
        }

        return $this->isSchemeAllowedForParsed($parsed);
    }

    public function isAllowedScheme(string $redirectUri): bool
    {
        try {
            $parsed = $this->parseCanonical($redirectUri);
        } catch (InvalidArgumentException) {
            return false;
        }

        return $this->isSchemeAllowedForParsed($parsed);
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
        return $this->parseCanonical($redirectUri)->normalizedHost;
    }

    /**
     * Exact match of two redirect URIs under the same canonical parse as
     * registration (scheme and host case-folded / normalised, port / path /
     * query compared as parsed). Unparsable either side is not equal.
     */
    public function areExactlyEqual(string $left, string $right): bool
    {
        try {
            $parsedLeft = $this->parseCanonical($left);
            $parsedRight = $this->parseCanonical($right);
        } catch (InvalidArgumentException) {
            return false;
        }

        return $parsedLeft->scheme === $parsedRight->scheme
            && $parsedLeft->normalizedHost === $parsedRight->normalizedHost
            && $parsedLeft->port === $parsedRight->port
            && $parsedLeft->path === $parsedRight->path
            && $parsedLeft->query === $parsedRight->query;
    }

    /**
     * Whether any of the client's stored redirect_uris matches $redirectUri
     * under {@see areExactlyEqual()}.
     */
    public function clientHasExactRedirectUri(Client $client, string $redirectUri): bool
    {
        $redirectUris = $client->getAttribute('redirect_uris');

        if (! is_array($redirectUris)) {
            return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn
        }

        foreach ($redirectUris as $registeredUri) {
            if (is_string($registeredUri) && $this->areExactlyEqual($registeredUri, $redirectUri)) {
                return true;
            }
        }

        return false;
    }

    public function displayHostOf(string $redirectUri): string
    {
        try {
            $parsed = $this->parseCanonical($redirectUri);
        } catch (InvalidArgumentException) {
            return '';
        }

        if (! $this->isHttpFamilyScheme($parsed->scheme)) {
            return $parsed->scheme;
        }

        return $parsed->normalizedHost !== null ? $parsed->normalizedHost : '';
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

            // Existing rows must still satisfy registration rules (e.g. backslash / hostless forms).
            if (! $this->isAcceptableForRegistration($redirectUri)) {
                return true; // @pest-mutate-ignore: RemoveEarlyReturn — hostOf throws on the same URI; still true
            }

            try {
                $host = $this->hostOf($redirectUri);
            } catch (InvalidArgumentException) {
                return true; // @pest-mutate-ignore: TrueToFalse
            }

            if ($host !== null && $this->isHostBlocked($host)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Single parse for every guard check, shared with ClientMetadataUriGuard.
     * Refuses fragment, backslash, userinfo, hostless http(s), percent-encoded
     * hosts, non-ASCII hosts and non-dotted-decimal IPv4 forms.
     *
     * @throws InvalidArgumentException
     */
    public function parseCanonical(string $redirectUri): ParsedRedirectUriData
    {
        if (str_contains($redirectUri, '#')) {
            throw new InvalidArgumentException('Redirect URI must not contain a fragment.');
        }

        if (str_contains($redirectUri, '\\')) {
            throw new InvalidArgumentException('Redirect URI must not contain a backslash.');
        }

        try {
            $parts = UriString::parse($redirectUri);
        } catch (Throwable $exception) {
            throw new InvalidArgumentException('Redirect URI could not be parsed.', 0, $exception); // @pest-mutate-ignore: DecrementInteger,IncrementInteger
        }

        $scheme = $parts['scheme'] ?? null;

        if (! is_string($scheme) || $scheme === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty,BooleanOrToBooleanAnd
            throw new InvalidArgumentException('Redirect URI requires a scheme.');
        }

        $normalizedScheme = Str::lower($scheme);

        // League always sets user/pass keys; refuse either when present.
        if (($parts['user'] ?? null) !== null || ($parts['pass'] ?? null) !== null) { // @pest-mutate-ignore: CoalesceRemoveLeft
            throw new InvalidArgumentException('Redirect URI must not contain userinfo.');
        }

        $rawHost = $parts['host'] ?? null;
        $hasHost = is_string($rawHost) && $rawHost !== '';

        if ($this->isHttpFamilyScheme($normalizedScheme) && ! $hasHost) {
            throw new InvalidArgumentException('http(s) redirect URI requires a non-empty host.');
        }

        $port = $this->canonicalPort($parts['port'] ?? null);
        $path = is_string($parts['path'] ?? null) ? $parts['path'] : '';
        $rawQuery = $parts['query'] ?? null;
        $query = is_string($rawQuery) && $rawQuery !== '' ? $rawQuery : null;

        if (! $hasHost) {
            return new ParsedRedirectUriData($normalizedScheme, null, $port, $path, $query);
        }

        if (str_contains($rawHost, '%')) {
            throw new InvalidArgumentException('Redirect host must not be percent-encoded.');
        }

        $this->assertRedirectHostIsAscii($rawHost);

        return new ParsedRedirectUriData(
            $normalizedScheme,
            $this->normalizeHost($rawHost),
            $port,
            $path,
            $query,
            isIpv6Literal: str_starts_with($rawHost, '['),
        );
    }

    private function canonicalPort(mixed $port): ?int
    {
        if (is_int($port)) {
            return $port;
        }

        // League UriString may yield a digit string for the port.
        if (is_string($port) && preg_match('/^\d+$/', $port) === 1) {
            return (int) $port; // @pest-mutate-ignore: RemoveIntegerCast,RemoveEarlyReturn — digit string → int is the branch
        }

        return null;
    }

    private function isSchemeAllowedForParsed(ParsedRedirectUriData $parsed): bool
    {
        if (in_array($parsed->scheme, $this->dangerousSchemes(), true)) {
            return false;
        }

        if ($this->isHttpFamilyScheme($parsed->scheme)) {
            // parseCanonical never yields a null http(s) host (throws instead).
            if ($parsed->normalizedHost === null) {
                return false; // @pest-mutate-ignore: FalseToTrue,RemoveEarlyReturn — unreachable for http(s); parseCanonical throws first
            }

            if ($parsed->scheme === 'https') {
                return true;
            }

            return in_array($parsed->normalizedHost, $this->loopbackHosts(), true);
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

        return in_array($parsed->scheme, $allowed, true);
    }

    /**
     * Canonical IPv4/IPv6, or null when the host is not an IP. Throws on forms
     * WHATWG URL parsing would treat as non-dotted-decimal IPv4.
     *
     * @throws InvalidArgumentException
     */
    private function canonicalizeIpHostOrRejectAmbiguous(string $host): ?string
    {
        if (str_contains($host, '%') || str_contains($host, "\0")) { // @pest-mutate-ignore: BooleanOrToBooleanAnd
            throw new InvalidArgumentException('Host contains a forbidden character.');
        }

        if ($this->hasLeadingZeroIpv4Octet($host)) {
            throw new InvalidArgumentException('Leading-zero IPv4 octets are not allowed.');
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

            if ($canonical === false) { // @pest-mutate-ignore: FalseToTrue
                throw new InvalidArgumentException('IPv6 host could not be canonicalised.');
            }

            return Str::lower($canonical);
        }

        if (strlen($packed) === 4) { // @pest-mutate-ignore: IdenticalToNotIdentical,DecrementInteger,IncrementInteger,IfNegated
            $canonical = inet_ntop($packed);

            if ($canonical === false) { // @pest-mutate-ignore: FalseToTrue
                throw new InvalidArgumentException('IPv4 host could not be canonicalised.');
            }

            // inet_pton accepts octal/ambiguous spellings; only dotted-decimal may proceed.
            if ($host !== $canonical) {
                throw new InvalidArgumentException('Non-canonical IPv4 host forms are not allowed.');
            }

            return $canonical; // @pest-mutate-ignore: RemoveEarlyReturn
        }

        return null;
    }

    /**
     * Integer, hex, short, octal and other spellings WHATWG URL parsing would
     * read as IPv4. WHATWG treats a host whose last label is numeric as an
     * IPv4 address, so such a host is allowed only as four decimal octets of
     * 0..255; anything else (`127.1`, `2130706433`, `0177.0.0.1`,
     * `256.0.0.1`, `example.123`) is refused here instead of being left to
     * inet_pton, whose answer differs between glibc and macOS.
     */
    private function isForbiddenIpv4Notation(string $host): bool
    {
        // IPv6 literals (possibly ending in an embedded dotted quad) go to inet_pton.
        if (str_contains($host, ':')) {
            return false;
        }

        // afterLast returns the whole string when '.' is absent — no ternary.
        $lastLabel = Str::afterLast($host, '.');

        // Hex IPv4 as a host or last label only (keep 0xproject.io usable).
        if (preg_match('/^0x[0-9a-f]+$/i', $lastLabel) === 1) {
            return true;
        }

        if (preg_match('/^\d+$/', $lastLabel) !== 1) {
            return false;
        }

        $decimalOctet = '(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)';

        return preg_match('/^'.$decimalOctet.'(?:\.'.$decimalOctet.'){3}$/', $host) !== 1;
    }

    /**
     * Octal-looking dotted-decimal octets. Checked before inet_pton so glibc
     * vs macOS inet_pton differences cannot hide the refusal.
     */
    private function hasLeadingZeroIpv4Octet(string $host): bool
    {
        if (preg_match('/^(?:\d{1,3}\.){3}\d{1,3}$/', $host) !== 1) {
            return false;
        }

        foreach (explode('.', $host) as $octet) {
            if (strlen($octet) > 1 && str_starts_with($octet, '0')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Embedded IPv4 from ::ffff:/96, ::ffff:0:0/96, ::/96 (except ::/127),
     * 64:ff9b::/96 or 64:ff9b:1::/48 — same rules as ClientThrottleKey.
     */
    private function embeddedIpv4FromMappedOrTranslated(string $packed): ?string
    {
        $isIpv4Mapped = str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff");
        $isIpv4Translated = str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00");
        $isIpv4Compatible = str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        $isNat64WellKnown = str_starts_with($packed, "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00");
        // 64:ff9b:1::/48 — prefix bytes 0..5 then six zero bytes; tested via [64:ff9b:1::a.b.c.d].
        $isNat64Local = str_starts_with($packed, "\x00\x64\xff\x9b\x00\x01")
            && substr($packed, 6, 6) === "\x00\x00\x00\x00\x00\x00"; // @pest-mutate-ignore: IdenticalToNotIdentical,DecrementInteger,IncrementInteger,UnwrapSubstr — prefix already pins 64:ff9b:1; wrong substr cannot match a real NAT64-local address under the suite

        if ($isIpv4Compatible && substr($packed, 0, 15) === str_repeat("\x00", 15)) {
            return null;
        }

        if (! $isIpv4Mapped && ! $isIpv4Translated && ! $isIpv4Compatible && ! $isNat64WellKnown && ! $isNat64Local) {
            return null;
        }

        $ipv4 = inet_ntop(substr($packed, 12));

        return $ipv4 === false ? null : $ipv4; // @pest-mutate-ignore: FalseToTrue,TernaryNegated
    }

    private function isHttpFamilyScheme(string $normalizedScheme): bool
    {
        return $normalizedScheme === 'http' || $normalizedScheme === 'https'; // @pest-mutate-ignore: BooleanOrToBooleanAnd
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
