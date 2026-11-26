<?php

declare(strict_types=1);

/**
 * This repo's settings for the shared `NamingArchitectureTest.php` (qiick standards).
 *
 * Written once by the sync, never overwritten or checked: it is this repo's own.
 * Package-only rules (no Foundation / parse_url / Signaculum in src/, @api surface)
 * are in `PackageArchitectureTest.php`.
 *
 * Public API names follow the binding design (not the shared Contract/Enum suffix
 * table): design-mandated types are listed under ignoring with reasons as they land.
 */
return [
    'namespace' => 'Qiick\McpOAuth',

    'ignoring' => [
        'Contracts' => [
            // Design §3.2: contract names without Contract suffix.
            'Qiick\McpOAuth\Contracts\AdminSwitch',
            'Qiick\McpOAuth\Contracts\OAuthUserResolver',
            'Qiick\McpOAuth\Contracts\ConsentProvider',
            'Qiick\McpOAuth\Contracts\GrantStore',
            'Qiick\McpOAuth\Contracts\GrantAuthorizer',
            'Qiick\McpOAuth\Contracts\ApiKeyDoor',
            'Qiick\McpOAuth\Contracts\McpCredentialBinder',
            'Qiick\McpOAuth\Contracts\AuditLogger',
            'Qiick\McpOAuth\Contracts\ConsentView',
        ],
        'Data' => [
            // Design §3.2 DTOs: names are the API, not *Data.
            'Qiick\McpOAuth\Data\ClientInfo',
            'Qiick\McpOAuth\Data\ConsentOption',
            'Qiick\McpOAuth\Data\ConsentOptions',
            'Qiick\McpOAuth\Data\ConsentDecision',
            'Qiick\McpOAuth\Data\GrantRecord',
            'Qiick\McpOAuth\Data\ConsentPage',
            'Qiick\McpOAuth\Data\AuthorizationDecision',
            // Enum lives beside the DTOs; naming rule targets classes only, but
            // keep the FQCN listed if a future rule expands.
            'Qiick\McpOAuth\Data\RevocationReason',
        ],
        'Events' => [
            // Design §5.5: verb past-tense names, no Event suffix.
            'Qiick\McpOAuth\Events\McpOAuthEnabled',
            'Qiick\McpOAuth\Events\McpOAuthDisabled',
            'Qiick\McpOAuth\Events\McpClientRegistered',
            'Qiick\McpOAuth\Events\McpConsentApproved',
            'Qiick\McpOAuth\Events\McpConsentDenied',
            'Qiick\McpOAuth\Events\McpGrantRevoked',
            'Qiick\McpOAuth\Events\McpRefreshTokenReused',
            'Qiick\McpOAuth\Events\McpTokenRevoked',
            'Qiick\McpOAuth\Events\McpRevokedRecordsPurged',
            'Qiick\McpOAuth\Events\McpClientBlocked',
            'Qiick\McpOAuth\Events\McpRedirectHostBlocked',
            'Qiick\McpOAuth\Events\McpRedirectHostUnblocked',
            'Qiick\McpOAuth\Events\McpUnusedClientsPruned',
            'Qiick\McpOAuth\Events\McpPassportKeysMissing',
        ],
        // Root @api services use design names (not Services\*Service).
        'Services' => [
            'Qiick\McpOAuth\McpOAuthServer',
            'Qiick\McpOAuth\AccessTokenAuthenticator',
            'Qiick\McpOAuth\RedirectUriGuard',
            'Qiick\McpOAuth\ClientMetadataUriGuard',
            'Qiick\McpOAuth\ClientThrottleKey',
            'Qiick\McpOAuth\McpOAuthReadiness',
            'Qiick\McpOAuth\McpBearerTokenResponse',
            'Qiick\McpOAuth\McpOAuthRoutes',
        ],
    ],

    'suffixes' => [],

    'controllerPublicMethods' => [],
];
