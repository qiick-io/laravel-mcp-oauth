<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Qiick\Outbound\Contracts\HostResolver;
use Qiick\Outbound\Enums\OutboundTransportErrorKindEnum;
use Qiick\Outbound\Http\OutboundHttpException;
use Qiick\Outbound\Ssrf\DnsHostResolver;

/**
 * Classifies an empty DNS answer as transient before the outbound guard
 * checks the returned addresses against its destination policy.
 *
 * @internal
 */
final class ClientMetadataHostResolver implements HostResolver
{
    public function __construct(private readonly HostResolver $resolver = new DnsHostResolver) {}

    /**
     * @return list<string>
     *
     * @throws OutboundHttpException when DNS supplies no addresses
     */
    public function resolve(string $host): array
    {
        $addresses = $this->resolver->resolve($host);

        if ($addresses === []) {
            throw OutboundHttpException::forTransport(OutboundTransportErrorKindEnum::Dns, 'Client metadata host could not be resolved.');
        }

        return $addresses;
    }
}
