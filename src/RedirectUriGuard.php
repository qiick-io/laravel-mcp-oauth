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
    /** @var list<string> */
    private const array DANGEROUS_SCHEMES = [
        'javascript',
        'data',
        'vbscript',
        'file',
    ];

    /** @var list<string> */
    private const array LOOPBACK_HOSTS = [
        '127.0.0.1',
        'localhost',
        '::1',
    ];

    public function __construct(
        private readonly BlockedHostCatalog $blockedHosts = new BlockedHostCatalog,
    ) {}

    public function isAcceptableForRegistration(string $redirectUri): bool
    {
        if (str_contains($redirectUri, '#')) {
            return false;
        }

        try {
            $parts = UriString::parse($redirectUri);
        } catch (Throwable) {
            return false;
        }

        $scheme = $parts['scheme'] ?? null;

        if (! is_string($scheme) || $scheme === '') {
            return false;
        }

        if (in_array(Str::lower($scheme), self::DANGEROUS_SCHEMES, true)) {
            return false;
        }

        $rawHost = $parts['host'] ?? null;

        if (! is_string($rawHost) || $rawHost === '') {
            return true;
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

        if (! is_string($scheme) || $scheme === '') {
            return false;
        }

        $normalizedScheme = Str::lower($scheme);

        if (in_array($normalizedScheme, self::DANGEROUS_SCHEMES, true)) {
            return false;
        }

        if ($normalizedScheme === 'https') {
            return true;
        }

        if ($normalizedScheme === 'http') {
            $rawHost = $parts['host'] ?? null;

            if (! is_string($rawHost) || $rawHost === '') {
                return false;
            }

            try {
                $host = $this->normalizeHost($rawHost);
            } catch (InvalidArgumentException) {
                return false;
            }

            return in_array($host, self::LOOPBACK_HOSTS, true);
        }

        $customSchemes = config('mcp.custom_schemes', []);

        if (! is_array($customSchemes)) {
            return false;
        }

        $allowed = [];

        foreach ($customSchemes as $value) {
            if (is_string($value) && $value !== '') {
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

        $idnaInfo = [];
        $asciiHost = idn_to_ascii(
            $normalizedHost,
            IDNA_DEFAULT | IDNA_NONTRANSITIONAL_TO_ASCII | IDNA_USE_STD3_RULES,
            INTL_IDNA_VARIANT_UTS46,
            $idnaInfo,
        );

        $idnaErrors = is_array($idnaInfo) && isset($idnaInfo['errors']) && is_int($idnaInfo['errors'])
            ? $idnaInfo['errors']
            : 0;

        if (
            $asciiHost === false
            || $asciiHost === ''
            || str_contains($asciiHost, '?')
            || $idnaErrors !== 0
        ) {
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
            throw new InvalidArgumentException('Redirect URI could not be parsed.', 0, $exception);
        }

        $rawHost = $parts['host'] ?? null;

        if (! is_string($rawHost) || $rawHost === '') {
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
        if ($normalizedScheme !== '' && ! in_array($normalizedScheme, ['https', 'http'], true)) {
            return $normalizedScheme;
        }

        $rawHost = $parts['host'] ?? null;

        if (is_string($rawHost) && $rawHost !== '') {
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
            if ($blockedHost === '') {
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

        if (! is_array($redirectUris)) {
            return false;
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
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            return substr($host, 1, -1);
        }

        return $host;
    }
}
