<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Data;

use Illuminate\Http\Request;

/**
 * A single resource selected at the token endpoint. After validating the
 * credential, the vendor bridge adds the exact grant it belongs to.
 *
 * @internal
 */
final readonly class TokenResourceSelectionData
{
    public const string REQUEST_ATTRIBUTE = 'mcp_oauth_token_resource';

    public function __construct(
        public string $identifier,
        public string $scope,
        public ?string $grantId = null,
    ) {}

    public static function from(Request $request): ?self
    {
        $selection = $request->attributes->get(self::REQUEST_ATTRIBUTE);

        return $selection instanceof self ? $selection : null;
    }
}
