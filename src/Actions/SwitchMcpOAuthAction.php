<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Actions;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\Route;
use Qiick\McpOAuth\Contracts\AdminSwitch;
use Qiick\McpOAuth\Events\McpOAuthDisabled;
use Qiick\McpOAuth\Events\McpOAuthEnabled;
use Qiick\McpOAuth\Exceptions\McpOAuthCannotBeEnabledException;
use Qiick\McpOAuth\Internal\PassportUserIdentifier;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * An admin flips the product's OAuth switch (design §4.3). The product owns
 * the store behind {@see AdminSwitch} and writes it through `$persist`; the
 * package owns the rules around it:
 *
 * - switching on is refused, with a reason to show, while OAuth could not
 *   serve: Passport keys missing or not one usable pair, APP_URL not a
 *   valid issuer, or a foreign `passport.*` route;
 * - switching off is always allowed and leaves grants, clients and blocked
 *   hosts in place;
 * - either way {@see McpOAuthEnabled} or {@see McpOAuthDisabled} is
 *   dispatched, with the actor, once the store is written.
 */
final class SwitchMcpOAuthAction
{
    public function __construct(
        private readonly McpOAuthServer $mcpOAuthServer,
        private readonly Dispatcher $events,
    ) {}

    /**
     * @param  Closure(bool): void  $persist  writes the product's switch store
     *
     * @throws McpOAuthCannotBeEnabledException
     */
    public function execute(bool $isEnabled, ?Authenticatable $actor, Closure $persist): void
    {
        if ($isEnabled) {
            $this->assertCanServe();
        }

        $persist($isEnabled);

        $actorIdentifier = $actor === null ? null : PassportUserIdentifier::of($actor);
        $this->events->dispatch($isEnabled ? new McpOAuthEnabled($actorIdentifier) : new McpOAuthDisabled($actorIdentifier));
    }

    /**
     * @throws McpOAuthCannotBeEnabledException
     */
    private function assertCanServe(): void
    {
        if (! $this->mcpOAuthServer->hasPassportKeys()) {
            throw new McpOAuthCannotBeEnabledException('OAuth cannot be switched on while the Passport keys are missing: run passport:keys.');
        }

        if (! $this->mcpOAuthServer->hasUsablePassportKeyPair()) {
            throw new McpOAuthCannotBeEnabledException('OAuth cannot be switched on: the Passport keys are not a usable matching pair.');
        }

        if (! $this->mcpOAuthServer->hasAbsoluteIssuer()) {
            throw new McpOAuthCannotBeEnabledException('OAuth cannot be switched on until APP_URL is an absolute http(s) URL.');
        }

        if (! Route::has('passport.token')) {
            throw new McpOAuthCannotBeEnabledException('OAuth cannot be switched on until McpOAuthRoutes::register() mounts its routes.');
        }

        $foreignRouteNames = McpOAuthRoutes::foreignPassportRouteNames();

        if ($foreignRouteNames !== []) {
            throw new McpOAuthCannotBeEnabledException('OAuth cannot be switched on beside another Passport server: '.implode(', ', $foreignRouteNames).'.');
        }
    }
}
