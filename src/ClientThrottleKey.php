<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Http\Request;

/**
 * Rate-limit identity for registration, token and /mcp auth failures.
 *
 * Uses {@see Request::ip()} (TrustProxies applies). IPv4 as-is; IPv4-mapped
 * (`::ffff:`), IPv4-compatible (`::a.b.c.d`) and NAT64 (`64:ff9b::/96`) unmap to
 * the embedded IPv4; other IPv6 keys as `v6:` plus the /64 prefix.
 *
 * @api
 */
final class ClientThrottleKey
{
    public static function fromRequest(Request $request): string
    {
        $ipAddress = $request->ip() ?? 'unknown';
        $packed = @inet_pton($ipAddress);

        if ($packed === false) {
            return $ipAddress;
        }

        if (strlen($packed) === 16) {
            $embeddedIpv4 = self::embeddedIpv4FromMappedOrTranslated($packed);

            if ($embeddedIpv4 !== null) {
                return $embeddedIpv4;
            }

            return 'v6:'.bin2hex(substr($packed, 0, 8));
        }

        return $ipAddress;
    }

    /**
     * Embedded IPv4 from ::ffff:/96, ::/96 (IPv4-compatible) or 64:ff9b::/96 (NAT64).
     */
    private static function embeddedIpv4FromMappedOrTranslated(string $packed): ?string
    {
        $prefix = substr($packed, 0, 12);
        $isIpv4Mapped = $prefix === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";
        $isIpv4Compatible = $prefix === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        $isNat64WellKnown = $prefix === "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00";

        if (! $isIpv4Mapped && ! $isIpv4Compatible && ! $isNat64WellKnown) {
            return null;
        }

        return inet_ntop(substr($packed, 12)) ?: null;
    }
}
