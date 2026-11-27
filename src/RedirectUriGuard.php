<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Passport\Client;
use League\Uri\UriString;
use LogicException;
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
            IDNA_DEFAULT | IDNA_USE_STD3_RULES,
            INTL_IDNA_VARIANT_UTS46,
        );

        // idn_to_ascii returns false on STD3/IDNA failure (an input that maps
        // to nothing included); '?' is the legacy soft failure.
        if ($asciiHost === false || str_contains($asciiHost, '?')) {
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
        /** @var array<mixed> $redirectUris Passport's redirectUris accessor always returns an array */
        $redirectUris = $client->getAttribute('redirect_uris');

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

        if ($parsed->normalizedHost === null) {
            throw new LogicException('parseCanonical() returned an http(s) URI without a host.');
        }

        return $parsed->normalizedHost;
    }

    public function isHostBlocked(string $host): bool
    {
        try {
            $normalizedHost = $this->normalizeHost($host);
        } catch (InvalidArgumentException) {
            return true;
        }

        foreach ($this->blockedHosts->all() as $blockedHost) {
            // An empty or malformed row cannot normalise and is skipped.
            try {
                $normalizedBlocked = $this->normalizeHost($blockedHost->host);
            } catch (InvalidArgumentException) {
                continue;
            }

            if ($normalizedHost === $normalizedBlocked) {
                return true;
            }

            if ($blockedHost->shouldMatchSubdomains && str_ends_with($normalizedHost, '.'.$normalizedBlocked)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A redirect a native app receives: loopback http or a private-use scheme
     * (RFC 8252 §7.1, §7.3). DCR infers `application_type` from it when the
     * client sends none (OIDC Registration defaults to `web`, which would
     * mislabel every desktop MCP client). An unparseable URI is not native.
     */
    public function isNativeRedirectUri(string $redirectUri): bool
    {
        try {
            $parsed = $this->parseCanonical($redirectUri);
        } catch (InvalidArgumentException) {
            return false;
        }

        if ($parsed->scheme === 'https') {
            return false;
        }

        return $parsed->scheme !== 'http' || in_array($parsed->normalizedHost, $this->loopbackHosts(), true);
    }

    /**
     * Loopback http (RFC 8252 §7.3): the code reaches whatever listens on
     * that port of the user's machine, so a client registered with only such
     * redirects gets a warning on the consent page (S3). An unparseable URI
     * is not loopback.
     */
    public function isLoopbackRedirectUri(string $redirectUri): bool
    {
        try {
            $parsed = $this->parseCanonical($redirectUri);
        } catch (InvalidArgumentException) {
            return false;
        }

        return $parsed->scheme === 'http' && in_array($parsed->normalizedHost, $this->loopbackHosts(), true);
    }

    public function clientHasBlockedRedirectHost(Client $client): bool
    {
        /** @var array<mixed> $redirectUris Passport's redirectUris accessor always returns an array */
        $redirectUris = $client->getAttribute('redirect_uris');

        foreach ($redirectUris as $redirectUri) {
            if (! is_string($redirectUri)) {
                continue;
            }

            // Existing rows must still satisfy registration rules (e.g. backslash /
            // hostless forms, non-loopback http); passing them means the parse succeeded.
            if (! $this->isAcceptableForRegistration($redirectUri)) {
                return true;
            }

            $host = $this->hostOf($redirectUri);

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
     * Parsing only, not validation: it does not apply the scheme allow-list
     * (dangerous schemes pass), the loopback-only rule for http, the
     * unspecified-address rule or the blocklist. Use
     * {@see isAcceptableForRegistration()} and {@see isHostBlocked()} to
     * decide whether a URI is allowed.
     *
     * @internal public only so ClientMetadataUriGuard shares the same parse
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
            throw new InvalidArgumentException('Redirect URI could not be parsed.', previous: $exception);
        }

        // League always returns every component key; an absent one is null.
        $scheme = $parts['scheme'];

        if ($scheme === null) {
            throw new InvalidArgumentException('Redirect URI requires a scheme.');
        }

        $normalizedScheme = Str::lower($scheme);

        if ($parts['user'] !== null || $parts['pass'] !== null) {
            throw new InvalidArgumentException('Redirect URI must not contain userinfo.');
        }

        $rawHost = $parts['host'];
        $hasHost = $rawHost !== null && $rawHost !== '';

        if ($this->isHttpFamilyScheme($normalizedScheme) && ! $hasHost) {
            throw new InvalidArgumentException('http(s) redirect URI requires a non-empty host.');
        }

        $port = $parts['port'];
        $path = $parts['path'];
        // `cb?` and `cb` are the same redirect: an empty query is no query.
        $query = $parts['query'] === '' ? null : $parts['query'];

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

    private function isSchemeAllowedForParsed(ParsedRedirectUriData $parsed): bool
    {
        if (in_array($parsed->scheme, $this->dangerousSchemes(), true)) {
            return false;
        }

        // 0.0.0.0 and :: reach services on the user's own machine on Linux and
        // macOS, so they are never a valid destination for any scheme.
        if (in_array($parsed->normalizedHost, ['0.0.0.0', '::'], true)) {
            return false;
        }

        if ($this->isHttpFamilyScheme($parsed->scheme)) {
            // parseCanonical never yields a null http(s) host (throws instead).
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
            if (is_string($value)) {
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
        if (str_contains($host, '%') || str_contains($host, "\0")) {
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

            // inet_ntop writes IPv6 in lower case.
            return $this->formatPackedIp($packed);
        }

        // The only other inet_pton result is four IPv4 bytes.
        $canonical = $this->formatPackedIp($packed);

        // inet_pton accepts octal/ambiguous spellings; only dotted-decimal may proceed.
        if ($host !== $canonical) {
            throw new InvalidArgumentException('Non-canonical IPv4 host forms are not allowed.');
        }

        return $canonical;
    }

    /**
     * inet_ntop fails only on a length other than 4 or 16 bytes, which
     * inet_pton never produces.
     */
    private function formatPackedIp(string $packedAddress): string
    {
        $formattedAddress = inet_ntop($packedAddress);

        if ($formattedAddress === false) {
            throw new LogicException('formatPackedIp() was given a packed address of the wrong length.');
        }

        return $formattedAddress;
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
            && substr($packed, 6, 6) === "\x00\x00\x00\x00\x00\x00";

        if ($isIpv4Compatible && substr($packed, 0, 15) === str_repeat("\x00", 15)) {
            return null;
        }

        if (! $isIpv4Mapped && ! $isIpv4Translated && ! $isIpv4Compatible && ! $isNat64WellKnown && ! $isNat64Local) {
            return null;
        }

        return $this->formatPackedIp(substr($packed, 12));
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
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
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
