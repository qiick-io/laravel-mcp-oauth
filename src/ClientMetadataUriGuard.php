<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Str;
use InvalidArgumentException;
use LogicException;
use Qiick\McpOAuth\Internal\BlockedHostCatalog;

/**
 * Validation for DCR logo_uri / client_uri only: http(s) to a public host.
 *
 * Starts from {@see RedirectUriGuard::parseCanonical()}, so fragment,
 * backslash, userinfo, percent-encoded or non-ASCII hosts and every
 * non-dotted-decimal IPv4 spelling are refused exactly as for redirect URIs.
 * On top of that, nothing a browser or a future server-side fetch could reach
 * inside the operator's network is accepted:
 *
 * - internal names: single-label hosts, `localhost`, `*.localhost`,
 *   `*.local`, `*.lan`, `home.arpa` (RFC 8375) and `*.internal` (cloud
 *   metadata such as `metadata.google.internal`);
 * - IPv6 literals that embed an IPv4 address (mapped, translated, NAT64,
 *   6to4, Teredo), whatever that address is: there is no honest reason to write a
 *   public IPv4 that way;
 * - private, reserved, shared (CGNAT), benchmarking, IETF protocol,
 *   documentation, discard, former relay and multicast IP literals.
 *
 * DNS is never resolved: nothing fetches these URIs today, so a name that
 * resolves to an internal address (`127.0.0.1.nip.io`) stays a fetch-time
 * concern for whichever consumer starts fetching.
 *
 * @internal
 */
final class ClientMetadataUriGuard
{
    public function __construct(
        private readonly RedirectUriGuard $redirectUriGuard = new RedirectUriGuard(new BlockedHostCatalog([])),
    ) {}

    public function isAcceptable(string $uri): bool
    {
        try {
            $parsedUri = $this->redirectUriGuard->parseCanonical($uri);
        } catch (InvalidArgumentException) {
            return false;
        }

        if ($parsedUri->scheme !== 'http' && $parsedUri->scheme !== 'https') {
            return false;
        }

        $host = $parsedUri->normalizedHost;

        if ($host === null) {
            throw new LogicException('parseCanonical() returned an http(s) URI without a host.');
        }

        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            return $this->isPublicHostname($host);
        }

        if ($parsedUri->isIpv6Literal && filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return false;
        }

        return $this->isPublicIpLiteral($host);
    }

    private function isPublicHostname(string $host): bool
    {
        if (! str_contains($host, '.')) {
            return false;
        }

        if ($host === 'home.arpa' || str_ends_with($host, '.home.arpa')) {
            return false;
        }

        return ! in_array(Str::afterLast($host, '.'), $this->internalNameSuffixes(), true);
    }

    private function isPublicIpLiteral(string $ipAddress): bool
    {
        $isOutsidePrivateAndReservedRanges = filter_var(
            $ipAddress,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;

        if (! $isOutsidePrivateAndReservedRanges) {
            return false;
        }

        foreach ($this->extraRefusedIpRanges() as [$rangeStart, $prefixLength]) {
            if ($this->isInRange($ipAddress, $rangeStart, $prefixLength)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Prefix match on the address bits; an IPv4 address never matches an IPv6
     * range (and the reverse) because the bit lengths differ.
     */
    private function isInRange(string $ipAddress, string $rangeStart, int $prefixLength): bool
    {
        $addressBits = $this->bitsOf($ipAddress);
        $rangeBits = $this->bitsOf($rangeStart);

        return strlen($addressBits) === strlen($rangeBits)
            && substr($addressBits, 0, $prefixLength) === substr($rangeBits, 0, $prefixLength);
    }

    private function bitsOf(string $ipAddress): string
    {
        $packedAddress = inet_pton($ipAddress);

        // Callers pass validated IP literals, so this never fires.
        if ($packedAddress === false) {
            throw new LogicException('bitsOf() was given something other than an IP literal.');
        }

        $bits = '';

        foreach (str_split($packedAddress) as $packedByte) {
            $bits .= sprintf('%08b', ord($packedByte));
        }

        return $bits;
    }

    /**
     * IP ranges filter_var's private / reserved flags do not cover.
     *
     * @return list<array{0: string, 1: int}>
     */
    private function extraRefusedIpRanges(): array
    {
        return [
            ['100.64.0.0', 10], // shared address space (CGNAT), RFC 6598
            ['192.0.0.0', 24], // IETF protocol assignments, RFC 6890
            ['198.18.0.0', 15], // benchmarking, RFC 2544
            // Multicast (224.0.0.0/4) and the reserved 240.0.0.0/4, which
            // filter_var's reserved flag refuses too: one /3 for both.
            ['224.0.0.0', 3],
            ['ff00::', 8], // IPv6 multicast
            ['2002::', 16], // 6to4 embeds an IPv4 address, RFC 3056
            ['2001::', 32], // Teredo embeds an obfuscated IPv4 address, RFC 4380
            ['2001:db8::', 32], // IPv6 documentation, RFC 3849
            ['100::', 64], // IPv6 discard-only, RFC 6666
            ['192.0.2.0', 24], // TEST-NET-1, RFC 5737
            ['198.51.100.0', 24], // TEST-NET-2, RFC 5737
            ['203.0.113.0', 24], // TEST-NET-3, RFC 5737
            ['192.88.99.0', 24], // former 6to4 relay anycast, RFC 7526
        ];
    }

    /**
     * Top-level labels that only resolve inside a host or a private network.
     *
     * @return list<string>
     */
    private function internalNameSuffixes(): array
    {
        return [
            'localhost',
            'local',
            'internal',
            'lan',
        ];
    }
}
