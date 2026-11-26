<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/header-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/header-light.svg">
    <img alt="laravel-mcp-oauth: OAuth for laravel/mcp endpoints" src=".github/assets/header-light.svg" width="100%">
  </picture>
</p>

# qiick/laravel-mcp-oauth

> **In development. Not released and not on Packagist yet: do not depend on it.**

OAuth authorization server for `laravel/mcp` endpoints in qiick Laravel
products. Consent plumbing, governed dynamic client registration, redirect URI
rules, refresh-token family revocation, RFC 6750 errors, fail-closed Passport
keys, and the `/mcp` Bearer door — built on Passport and `laravel/mcp`.

Part of the qiick fleet. Binding design:
`projects/qiick/packages/laravel-mcp-oauth-design.md` in the knowledge base
(answers: `decisions/2026-11-22-mcp-oauth-and-access-design-answers.md`).

## Status

Pre-`0.1.0`. Public APIs may change in any 0.x release; see [UPGRADING.md](./UPGRADING.md).
Do not require this package from production apps until a tagged release lands on
Packagist (Packagist publish only after Luca’s go). `1.0.0` needs a non-externa
adopter and Luca’s go.

## Requirements

- PHP `^8.3` with `ext-intl` and `ext-openssl`
- illuminate/console, contracts, database, http, routing, support
  `^12.41.1 \|\| ^13.0` (never `laravel/framework`)
- `laravel/passport ^13.12`, `laravel/mcp ^1.2`, `league/uri ^7.8`
- Optional: `inertiajs/inertia-laravel ^3.0` (default `ConsentView`)

## Install (when published)

```bash
composer require qiick/laravel-mcp-oauth:^0.1
php artisan vendor:publish --tag=mcp-oauth-config
php artisan vendor:publish --tag=passport-migrations
php artisan vendor:publish --tag=mcp-oauth-migrations
php artisan vendor:publish --tag=mcp-oauth-binding-stub
php artisan passport:keys
```

The service provider is auto-discovered. Products implement the contracts
(`AdminSwitch`, `GrantStore`, `ConsentProvider`, …), call
`McpOAuthRoutes::register()` from their MCP routes file, and keep OAuth off
until keys exist and the admin switch is flipped.

`McpOAuthRoutes::register()` serves DCR, authorize, token, revocation (RFC 7009)
and the RFC 8414 / RFC 9728 discovery documents. Do not also call
`Mcp::oauthRoutes()`: its documents are built from the request `Host` and sit
outside the off-gate, and its `oauth/register` would replace the package's.
With OAuth on, boot (or, with `route:cache`, the first request) fails while
any of its routes is mounted, and
`mcp-oauth:check` lists them.

Browser-based MCP clients (the MCP inspector, for example) call these endpoints
cross-origin. The package sets no CORS headers itself: add the paths to the
product's `config/cors.php`, where Laravel's `HandleCors` answers the preflight
before routing:

```php
'paths' => ['api/*', '.well-known/*', 'oauth/register', 'oauth/token', 'oauth/revoke', 'mcp'],
```

`mcp` is the MCP endpoint itself (`mcp-oauth.mcp_path`): a browser client
calls it cross-origin with the token it got.

Mount the package's door and challenge on the product's `/mcp` route. The
door replaces the product's own `/mcp` authentication middleware and sits
before its throttle; the challenge replaces laravel/mcp's
`AddWwwAuthenticateHeader`, which would overwrite the RFC 6750 error code:

```php
Mcp::web('/mcp', ProductServer::class)
    ->withoutMiddleware(AddWwwAuthenticateHeader::class)
    ->middleware([McpChallengeMiddleware::class, McpBearerDoorMiddleware::class, 'throttle:mcp']);
```

The door takes an API key through the product's `ApiKeyDoor` and an OAuth
access token through `AccessTokenAuthenticator` (audience, client, blocked
hosts, bound grant, `mcp:use`, then the product's `GrantAuthorizer`, on every
call), binds either through `McpCredentialBinder`, and answers 429 to an address
that failed `mcp_auth_failures_per_minute` times. With OAuth off it behaves as
before the package: every Bearer is an API key, and a 401 says
`Bearer realm="mcp", error="invalid_token"`. With OAuth on, every 401 and 403
points at the protected resource metadata built from `APP_URL`.

The product's settings page switches OAuth on and off through
`SwitchMcpOAuthAction`, which refuses to switch on (with a reason to show)
while OAuth could not serve, and dispatches `McpOAuthEnabled` or
`McpOAuthDisabled`. The product keeps its own store behind `AdminSwitch`, and
every write to that store must go through the action (behind the product's
admin permission and CSRF), or the rule can be bypassed:

```php
try {
    $switchMcpOAuth->execute($request->boolean('enabled'), $request->user(), fn (bool $isEnabled) => $settings->setMcpOAuth($isEnabled));
} catch (McpOAuthCannotBeEnabledException $exception) {
    return back()->withErrors(['enabled' => $exception->getMessage()]);
}
```

Mount the admin backend for MCP clients and blocked hosts inside the
product's own admin group, naming the permission middleware every route
needs. The routes stay up while OAuth is off, so an admin can still clean up:

```php
Route::middleware(['web', 'auth'])->prefix('admin')->group(
    fn () => McpOAuthAdminRoutes::register('permission:can-manage-mcp-clients'),
);
```

| Route | Does |
| --- | --- |
| `GET mcp-oauth-clients` | JSON: the package's clients (50 a page) and the blocked hosts |
| `POST mcp-oauth-clients/{client}/block` | revokes the client, its grants, tokens and codes |
| `POST mcp-oauth-clients/bulk-block` | the same for 1 to 100 distinct client UUIDs |
| `POST mcp-oauth-clients/blocked-hosts` | blocks a host (`match_mode` `exact` or, by default, with its subdomains) and every client that redirects there; a host already blocked keeps its first mode and reason |
| `DELETE mcp-oauth-clients/blocked-hosts/{id}` | lifts a block; blocked clients stay revoked |

Writes answer 204 to a JSON call and redirect back for a form or Inertia post.
Only clients the package registered are listed or blocked, never the product's
own Passport clients.

Mount Connected apps, where a signed-in user lists the MCP clients they
authorised and revokes one, inside the product's authenticated group. Like the
admin routes, they stay up while OAuth is off:

```php
Route::middleware(['web', 'auth'])->group(fn () => McpOAuthSettingsRoutes::register());
```

`GET settings/connected-apps` answers JSON (`connectedApps`: grant id, client,
scopes, display, dates); `DELETE settings/connected-apps/{grant}` revokes the
grant and every token bound to it, answering 204 to a JSON call and
redirecting back otherwise. A grant that is not the user's own active one is a
404.

Schedule the retention jobs. `mcp-oauth:purge-revoked` deletes what was revoked
more than `revoked_retention_days` (90) ago: clients the package registered,
the product's grants (through `GrantStore::purgeRevokedBefore()`, which may keep
rows under a legal hold) and consent records. `mcp-oauth:prune-unused-clients`
deletes DCR clients nobody authorised within `unused_client_retention_hours`
(24). Every command takes `--dry-run`. `mcp-oauth:check` reports whether OAuth
is on and ready and exits 1 when it is on but not ready:

```php
Schedule::command('mcp-oauth:prune-auth-code-exchanges')->daily()->onOneServer();
Schedule::command('mcp-oauth:purge-revoked')->daily()->onOneServer();
Schedule::command('mcp-oauth:prune-unused-clients')->hourly()->onOneServer();
```

## Threat model (short)

| Threat | Mitigation |
| --- | --- |
| Public DCR flood / phishing | Off by default (three gates); per-key and global caps; prune; admin block |
| Hostile redirect hosts | League URI only; ASCII hosts; UTS #46; exact/subdomain block |
| Host-header discovery poisoning | Issuer and resource from `APP_URL` only |
| Refresh-token theft / races | Atomic rotation; family + grant revocation; live binding required |
| Code replay | One-shot codes; a replay revokes the grant and every token issued with it |
| A token used after revocation | `/mcp` re-checks token, audience, client, blocked hosts and bound grant on every call; nothing cached |
| Credential guessing at `/mcp` | Per-address failure brake (429 before the credential is read). Clients behind one shared address (carrier NAT, a corporate egress) share the counter: raise `mcp_auth_failures_per_minute` or throttle sharper at the edge |
| Missing Passport keys | 503 `temporarily_unavailable`; switch refuses to turn on |

Full table: design §16.

## Public API (contracts and data)

Products implement `Qiick\McpOAuth\Contracts\*` (`AdminSwitch`, `GrantStore`,
`ConsentProvider`, `GrantAuthorizer`, `ApiKeyDoor`, `McpCredentialBinder`,
`AuditLogger`, `ConsentView`, `OAuthUserResolver`). Wire and consent shapes are
the `@api` DTOs under `Qiick\McpOAuth\Data` and events under
`Qiick\McpOAuth\Events`. Public ids are UUID strings only.

## Config

Publishable `config/mcp-oauth.php` (tag `mcp-oauth-config`). Env prefix
`MCP_OAUTH_*`. Redirect allowlists stay in `laravel/mcp`’s `mcp.redirect_domains`
and `mcp.custom_schemes`. Issuer is always `APP_URL`.

## Testing

```bash
composer test
composer lint
composer analyse
bash scripts/mutate-per-class.sh   # per-class MSI ≥ 95 once targets land
```

[docs/traceability.md](./docs/traceability.md) maps every design scenario
(S1–S81) to the tests that prove it, and lists what is still open.

CI: PHP 8.3/8.4/8.5 × Laravel 12/13 × lowest/stable, Pint, PHPStan max, Pest,
`composer validate --strict`, `composer audit`, database engine jobs, real HTTP
(`php -S`) once the `http` group exists, and qiick standards drift against
app-ui `v0.12.0`.

## License

[MIT](./LICENSE)
