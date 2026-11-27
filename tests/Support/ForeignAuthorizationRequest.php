<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Support;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

/**
 * A valid-looking authorization request of a class outside Passport's
 * unserialize allowlist: the pending-request check must refuse it.
 */
final class ForeignAuthorizationRequest extends AuthorizationRequest {}
