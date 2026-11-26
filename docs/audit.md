# Audit entries

The package writes one audit entry per security change through the product's
`AuditLogger` (design §3.1, standards review §5, S78). Without a product sink
a no-op logger takes them; `FakeAuditLogger` records them in tests.

## When an entry is written

`record()` runs inside the database transaction of the change it describes,
before the change's event:

- a sink that writes on the change's connection commits or rolls back with
  it, exactly once;
- a sink that throws rolls the change back, no event is dispatched and the
  exception reaches the caller, so a retry starts from the state before it
  (a denial leaves no evidence row, an unblock leaves the host blocked);
- a sink on another connection or outside the database should defer its
  write to the commit if an entry for a rolled-back change matters;
- a grant revoke writes the product's `GrantStore` last, after the token
  changes and the entry, holding the client's row lock: a failing sink
  leaves the grant active even in a store that commits on its own, and two
  concurrent revokes of one grant record one entry and one event. If
  Passport's transaction fails after such a store committed (its commit),
  the tokens and the entry are written again in a new transaction and the
  failure is reported: the revoke completes forward. A `GrantStore` on
  Passport's connection keeps all of it in one commit.

| Change | Transaction on | Then dispatched |
| --- | --- | --- |
| Consent approved | the package's connection, with the default one nested | `McpConsentApproved` |
| Consent denied | the package's connection | `McpConsentDenied` |
| Grant revoked from Connected apps, or by the client (RFC 7009 refresh token) | Passport's | `McpGrantRevoked`, `McpTokenRevoked` |
| Client blocked | Passport's | `McpClientBlocked` |
| Redirect host blocked, unblocked | the package's | `McpRedirectHostBlocked`, `McpRedirectHostUnblocked` |
| OAuth switched on or off | the default connection; the entry is written before the product's store | `McpOAuthEnabled`, `McpOAuthDisabled` |

## Entries

Properties hold ids, hosts and choices only: never a token, code, verifier,
callback URL, authorization header or request body (S79). The causer is the
`Authenticatable` who acted, or null for a client or the system.

| Event | Causer | `grantId` | Properties |
| --- | --- | --- | --- |
| `oauth_consent_approved` | the user | the new grant | `client_id`, `redirect_host`, `scopes`, `resources` |
| `oauth_consent_denied` | the user | null | `client_id`, `redirect_host` |
| `oauth_grant_revoked` | the user (Connected apps) or null (RFC 7009) | the grant | `client_id`, `redirect_host` (from the approval's consent record; null once purged), `reason` (`user` or `client`) |
| `oauth_client_blocked` | the admin | null | `client_id` |
| `oauth_redirect_host_blocked` | the admin | null | `host`, `match_mode` |
| `oauth_redirect_host_unblocked` | the admin | null | `host` |
| `mcp_oauth_enabled`, `mcp_oauth_disabled` | the admin, or null | null | none |

An RFC 7009 revoke of an access token leaves the grant in place and writes no
entry; `McpTokenRevoked` reports it.

## Keeping the 1.5 activity log

A product that already logs OAuth activity under the 1.5 names (Externa's
`api-keys` log) keeps those names and property shapes in its sink; the
package never writes the activity log itself. The adapter maps:

| Package entry | 1.5 activity event | Properties the adapter writes |
| --- | --- | --- |
| `oauth_consent_approved` | `oauth_authorized` | `oauth_client_id` from `client_id`, `redirect_host`, `scopes`; `name`, `role_id` and `collection_slugs` from the product's own grant found by `grantId` (also the `performedOn` subject) |
| `oauth_grant_revoked` | `oauth_revoked` | `oauth_client_id` from `client_id`, `name` and `scopes` from the product's grant, and `reason` (`client` for an RFC 7009 revoke, `user` for Connected apps) |
| `oauth_client_blocked` | `oauth_client_blocked` | `oauth_client_id` from `client_id`, `name` from the Passport client |
| `oauth_redirect_host_blocked` | `oauth_redirect_host_blocked` | `host` |
| `oauth_consent_denied`, `oauth_redirect_host_unblocked`, `mcp_oauth_enabled`, `mcp_oauth_disabled` | none in 1.5 | new events; log them under these names or drop them |

Each 1.5 entry is written once: the package records each change once, and
the 1.5 actions that wrote these entries are replaced by the package's.
