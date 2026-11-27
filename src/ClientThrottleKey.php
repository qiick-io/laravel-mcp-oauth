<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Http\Request;

/**
 * Rate-limit identity for registration, token and /mcp auth failures.
 *
 * Uses {@see Request::ip()} (TrustProxies applies). IPv4 as-is; IPv4-mapped
 * (`::ffff:`), IPv4-translated (`::ffff:0:a.b.c.d`), IPv4-compatible (`::a.b.c.d`
 * except `::/127`), NAT64 well-known (`64:ff9b::/96`) and local NAT64
 * (`64:ff9b:1::/48`) unmap to the embedded IPv4; other IPv6 keys as `v6:` plus
 * the /64 prefix.
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
     * Embedded IPv4 from ::ffff:/96, ::ffff:0:0/96, ::/96 (except ::/127),
     * 64:ff9b::/96 or 64:ff9b:1::/48.
     */
    private static function embeddedIpv4FromMappedOrTranslated(string $packed): ?string
    {
        $isIpv4Mapped = str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff");
        $isIpv4Translated = str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00");
        $isIpv4Compatible = str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        $isNat64WellKnown = str_starts_with($packed, "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00");
        $isNat64Local = str_starts_with($packed, "\x00\x64\xff\x9b\x00\x01")
            && substr($packed, 6, 6) === "\x00\x00\x00\x00\x00\x00";

        if ($isIpv4Compatible && substr($packed, 0, 15) === str_repeat("\x00", 15)) {
            // ::/127 (:: and ::1) are not IPv4-compatible addresses.
            return null;
        }

        if (! $isIpv4Mapped && ! $isIpv4Translated && ! $isIpv4Compatible && ! $isNat64WellKnown && ! $isNat64Local) {
            return null;
        }

        return inet_ntop(substr($packed, 12)) ?: null;
    }
}
