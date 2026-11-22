<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Str;
use InvalidArgumentException;
use League\Uri\UriString;
use Throwable;

/**
 * Validation for DCR logo_uri / client_uri only. Separate from
 * {@see RedirectUriGuard}: metadata URIs must be http(s) to a non-loopback,
 * non-private host (no custom schemes, no RFC 8252 loopback exception).
 *
 * @api
 */
final class ClientMetadataUriGuard
{
    public function isAcceptable(string $uri): bool
    {
        try {
            $parts = $this->parseHttpUri($uri);
        } catch (InvalidArgumentException) {
            return false;
        }

        $host = $parts['host'];

        if ($this->isIpLiteral($host)) {
            return $this->isPublicIpLiteral($host);
        }

        return $host !== ''; // @pest-mutate-ignore: EmptyStringToNotEmpty — empty host already threw above
    }

    /**
     * @return array{scheme: string, host: string}
     *
     * @throws InvalidArgumentException
     */
    private function parseHttpUri(string $uri): array
    {
        if (str_contains($uri, '#') || str_contains($uri, '\\')) {
            throw new InvalidArgumentException('Metadata URI must not contain a fragment or backslash.');
        }

        try {
            $parts = UriString::parse($uri);
        } catch (Throwable $exception) {
            throw new InvalidArgumentException('Metadata URI could not be parsed.', 0, $exception); // @pest-mutate-ignore: DecrementInteger,IncrementInteger
        }

        $scheme = $parts['scheme'] ?? null;

        if (! is_string($scheme) || $scheme === '') { // @pest-mutate-ignore: BooleanOrToBooleanAnd,EmptyStringToNotEmpty
            throw new InvalidArgumentException('Metadata URI requires a scheme.');
        }

        $normalizedScheme = Str::lower($scheme);

        if (! in_array($normalizedScheme, ['http', 'https'], true)) {
            throw new InvalidArgumentException('Metadata URI must use http or https.');
        }

        if (($parts['user'] ?? null) !== null || ($parts['pass'] ?? null) !== null) { // @pest-mutate-ignore: BooleanOrToBooleanAnd,CoalesceRemoveLeft
            throw new InvalidArgumentException('Metadata URI must not contain userinfo.');
        }

        $rawHost = $parts['host'] ?? null;

        if (! is_string($rawHost) || $rawHost === '') { // @pest-mutate-ignore: BooleanOrToBooleanAnd,EmptyStringToNotEmpty
            throw new InvalidArgumentException('Metadata URI requires a host.');
        }

        if (str_contains($rawHost, '%')) {
            throw new InvalidArgumentException('Metadata host must not be percent-encoded.');
        }

        $host = Str::lower(rtrim(trim($this->unwrapIpv6Host($rawHost)), '.')); // @pest-mutate-ignore: UnwrapRtrim,UnwrapTrim

        if ($host === '') { // @pest-mutate-ignore: EmptyStringToNotEmpty
            throw new InvalidArgumentException('Metadata host is empty.');
        }

        return [
            'scheme' => $normalizedScheme, // @pest-mutate-ignore: RemoveArrayItem
            'host' => $host,
        ];
    }

    private function unwrapIpv6Host(string $host): string
    {
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) { // @pest-mutate-ignore: BooleanAndToBooleanOr
            return substr($host, 1, -1); // @pest-mutate-ignore: DecrementInteger,IncrementInteger
        }

        return $host;
    }

    private function isIpLiteral(string $host): bool
    {
        return filter_var($host, FILTER_VALIDATE_IP) !== false;
    }

    private function isPublicIpLiteral(string $host): bool
    {
        return filter_var(
            $host,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE, // @pest-mutate-ignore: BitwiseOrToBitwiseAnd
        ) !== false;
    }
}
