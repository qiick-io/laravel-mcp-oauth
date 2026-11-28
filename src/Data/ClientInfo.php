<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

/**
 * Passport client facts shown on consent and in admin lists, with what the
 * client registered (RFC 7591) from its metadata row. Every field after
 * `isRedirectLoopback` is a client claim except the registration source and
 * the operator of a first-party client. Its shipped name is marked trusted.
 *
 * @api
 */
final readonly class ClientInfo
{
    /**
     * @param  list<string>  $redirectUris
     * @param  bool  $isRedirectLoopback  the callback this request returns to is loopback http (S3)
     * @param  string  $registrationSource  how the client came to exist (`dcr`, later `cimd`)
     * @param  list<string>  $contacts
     */
    public function __construct(
        public string $id,
        public string $name,
        public string $redirectHost,
        public array $redirectUris,
        public bool $isRedirectLoopback = false,
        public string $registrationSource = 'dcr',
        public ?string $clientUri = null,
        public ?string $logoUri = null,
        public ?string $policyUri = null,
        public ?string $tosUri = null,
        public array $contacts = [],
        public ?string $softwareId = null,
        public ?string $softwareVersion = null,
        public ?string $metadataDocumentUrl = null,
        public bool $nameIsSelfAsserted = true,
        public ?string $operatorName = null,
    ) {}
}
