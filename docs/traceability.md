# Traceability: design scenarios S1–S81

Each scenario of the design's test table (§11, `projects/qiick/packages/laravel-mcp-oauth-design.md` in the knowledge base) mapped to the tests that prove it. The S-numbers here are the design's. Some test titles carry the standards review's own S-numbers (`S2: CIMD runtime…`), which are a different list.

Status:

- **covered**: package tests prove it;
- **covered (#N)**: proved by an open pull request;
- **partial**: the package side is proved, part of the scenario is not;
- **product**: the scenario lives behind a product adapter (`ConsentProvider`, `GrantAuthorizer`, `ApiKeyDoor`, `McpCredentialBinder`, `AuditLogger`) and belongs in the product's suite;
- **gap**: not proved yet.

Paths are under `tests/`; `Http/RealHttpFlowTest` runs over real HTTP (`php -S`) on all four database engines.

| Id | Scenario | Status | Tests |
| --- | --- | --- | --- |
| S1 | Any gate off: every OAuth and discovery route 404 | covered | `Isolated/DiscoveryRouteTest` "with OAuth off answers every discovery document like a missing route"; the "with OAuth off matches an unregistered …" tests in `Isolated/DcrRegisterRouteTest`, `TokenEndpointRouteTest`, `RevocationRouteTest`, `AuthorizeConsentRouteTest`; `Unit/Http/EnsureMcpOAuthEnabledMiddlewareTest` |
| S2 | Admin switch off while config is on: 404 | covered | `Unit/McpOAuthServerTest` "is off unless config, admin switch and product MCP flag are all true"; `Http/RealHttpFlowTest` step 6 (admin switch) |
| S3 | MCP off with OAuth on: OAuth routes and `/mcp` 404 | partial | OAuth routes: `Unit/McpOAuthServerTest` (product MCP flag gate). `/mcp` is the product's route |
| S4 | Passport's own routes never registered | covered | `Feature/PassportBootTest` "always ignores Passport routes"; `Isolated/PassportRoutesAbsentTest` |
| S5 | Off: `/mcp` challenge unchanged, no metadata link | covered | `Isolated/McpDoorRouteTest` "with OAuth off keeps the plain challenge and the API-key door"; `Isolated/DiscoveryRouteTest` "leaves the /mcp challenge of laravel/mcp as if the package were absent" |
| S6 | Off: non-key Bearer is an unknown API key; API keys work | covered | `Isolated/McpDoorRouteTest` "with OAuth off takes any Bearer the product accepts"; `Http/RealHttpFlowTest` step 6 |
| S7 | Keys missing: OAuth routes 503; HTML 503 for a browser authorize | covered | `Isolated/AuthorizeConsentRouteTest` "answers a browser 503 page and a JSON 503"; the 503 tests in `DcrRegisterRouteTest` and `TokenEndpointRouteTest`; `Http/RealHttpFlowTest` step 7 |
| S8 | Keys missing: non-key Bearer 503 on `/mcp`; API key still works | covered | `Isolated/McpDoorRouteTest` "answers 503 for an OAuth token while the keys are missing"; `Http/RealHttpFlowTest` step 7 |
| S9 | Half-set env key pair counts as missing | covered | `Unit/McpOAuthServerTest` "treats a half-set env key pair as missing"; `Unit/McpOAuthServerMutationTest`; `Isolated/RetentionCommandsTest` "reports an incomplete env key pair" |
| S10 | World-readable key file counts as missing (503) | covered | `Unit/McpOAuthServerTest` "treats world-readable key files as missing"; `Unit/McpOAuthServerMutationTest` mode tests |
| S11 | Switch refuses to turn on without keys; unreadable store is off | covered (#44) | `Isolated/SwitchMcpOAuthTest`; `Unit/McpOAuthServerTest` "treats an unreadable admin switch store as off", "treats a throwing admin switch as off" |
| S12 | Readiness reports `passport_keys` only while enabled | covered | `Unit/McpOAuthServerTest` "reports passport_keys only while OAuth is enabled" |
| S13 | Issuer, resource and endpoints from `APP_URL`; `mcp.authorization_server` pinned | covered (#50) | `Isolated/DiscoveryRouteTest` "builds every URL from APP_URL, never from the Host header"; `Http/RealHttpFlowTest` step 1; `Feature/ServiceProviderTest` "pins laravel/mcp's authorization server to the issuer, unless the product set one" |
| S14 | Root and nested discovery shadow laravel/mcp's | covered | `Isolated/DiscoveryRouteTest` "publishes … root and nested", "serves the nested authorization server document only for the MCP path" |
| S15 | Metadata advertises only `mcp:use`, `code`, the two grants, `S256` | covered | `Isolated/DiscoveryRouteTest` (exact JSON); `Unit/McpOAuthServerTest` "builds the RFC 8414 and RFC 9728 documents" |
| S16 | `resource` required and exact at authorize and token | covered | `Isolated/TokenEndpointRouteTest` "requires the resource to name this MCP endpoint on both grants"; `Unit/McpOAuthServerTest` "compares the resource path exactly" |
| S17 | PKCE `S256` only; a JSON 400, never a redirect | covered | `Isolated/AuthorizeConsentRouteTest` "refuses an authorization request without PKCE S256 as JSON, never a redirect" |
| S18 | Code exchange without the verifier refused | covered | `Isolated/TokenEndpointRouteTest` "refuses a code exchange without the PKCE verifier" |
| S19 | Only `authorization_code` and `refresh_token`; device grant off | covered | `Isolated/TokenEndpointRouteTest` "accepts only the authorization code and refresh token grants", "refuses the password grant"; `Feature/PassportBootTest` device grant; `Isolated/PassportAuthCodeTtlTest` "keeps only the MCP grants" |
| S20 | Foreign wire scopes dropped; tokens carry only `mcp:use` | covered | `Isolated/AuthorizeConsentRouteTest` "drops foreign wire scopes"; `Isolated/TokenEndpointRouteTest` "exchanges a code for a bound token pair that names the wire scope"; `Feature/PassportScopeBootTest` |
| S21 | Token response names `scope=mcp:use` | covered | `Unit/McpBearerTokenResponseTest`; `Isolated/TokenEndpointRouteTest` |
| S22 | Fragments and dangerous schemes refused, even when listed | covered | `Unit/RedirectUriGuardTest` "refuses fragments and dangerous schemes even when listed as custom"; `Unit/RedirectUriGuardAdversarialTest` |
| S23 | `https`, loopback `http`, listed schemes accepted; other `http` refused | covered | `Unit/RedirectUriGuardTest` "accepts https and loopback http including IPv6"; `Unit/RedirectUriGuardCanonicalParseTest` N1; `Http/RealHttpFlowTest` step 2 |
| S24 | `http://[::1]` completes the whole flow | covered | `Http/RealHttpFlowTest` "runs the whole flow to tools/list with an IPv6 loopback callback" |
| S25 | Non-ASCII registered hosts refused | covered | `Unit/RedirectUriGuardTest` "refuses non-ASCII registered hosts"; `Unit/RedirectUriGuardAdversarialTest` |
| S26 | League `UriString` only; no `parse_url` in `src/` | covered | `Arch/PackageArchitectureTest` "src never calls parse_url"; `Unit/RedirectUriGuardAdversarialTest` "forbids parse_url anywhere under src" |
| S27 | Per-address registration limit | covered | `Isolated/DcrRegisterRouteTest` "limits unauthenticated registrations per address with Retry-After"; `Feature/RateLimiterBootTest` |
| S28 | Global cap answers 503 | covered | `Isolated/DcrRegisterRouteTest` "answers 503 when the global client cap is reached" |
| S29 | Throttle keys unmap `::ffff:`, `::a.b.c.d`, `64:ff9b::`; IPv6 by /64 | covered | `Unit/ClientThrottleKeyTest` |
| S30 | Throttle IP is `Request::ip()`; untrusted `X-Forwarded-For` ignored | covered | `Unit/ClientThrottleKeyTest` "ignores X-Forwarded-For when proxies are not trusted" |
| S31 | Prune: unused clients past retention; keeps ever-authorised and fresh ones | covered | `Isolated/RetentionCommandsTest` prune tests, the 23/24/25-hour boundary, B1 (grant purged) and M1 (authorised during the prune) |
| S32 | DCR refuses a blocked host | covered | `Isolated/DcrRegisterRouteTest` "refuses registration for a blocked redirect host" |
| S33 | Admin Unicode host stored as ASCII; invalid IDNA refused | covered | `Isolated/AdminBlockActionsTest` "blocks a host and its subdomains, normalised to ASCII", "refuses a host that does not normalise"; `Unit/RedirectUriGuardTest` |
| S34 | The NFC punycode form of a blocked IDN refused | covered | `Isolated/DcrRegisterRouteTest` "refuses the punycode of an IDN an admin blocked in Unicode, composed or not" (allowed before the block) |
| S35 | Exact or subdomain match; `notapp.test` ≠ `app.test` | covered | `Unit/RedirectUriGuardTest` "blocks exact hosts and subdomains but not sibling suffixes" |
| S36 | A host that does not normalise counts as blocked | covered | `Unit/RedirectUriGuardTest` "treats a host that does not normalise as blocked" |
| S37 | Existing clients refused at authorize, token and `/mcp` after a block | covered | `Isolated/AuthorizeConsentRouteTest`, `TokenEndpointRouteTest`, `McpDoorRouteTest` (blocked host); `Http/RealHttpFlowTest` step 5 |
| S38 | Token-endpoint block check reads the client id from HTTP Basic | covered | `Isolated/TokenEndpointRouteTest` "refuses a client whose redirect host was blocked, by body or HTTP Basic client_id" |
| S39 | Host block: short transaction, chunked revocation outside it | covered | `Isolated/AdminBlockActionsTest` "blocks every matching client across more than one chunk", "blocks a host without one transaction around the client walk" (one transaction per blocked client, never nested) |
| S40 | Bulk block: 1–100 distinct ids, each fully revoked | covered | `Isolated/AdminBlockActionsTest` bulk test and the 422 matrix |
| S41 | Blocking a client revokes it and every credential | covered | `Isolated/AdminBlockActionsTest` "blocks a client: revokes it, its grants, tokens and codes"; refusal of a revoked client in `McpDoorRouteTest`, `TokenEndpointRouteTest`, `AuthorizeConsentRouteTest` |
| S42 | A guest goes to login; the authorize query survives login | covered | `Isolated/AuthorizeConsentRouteTest` "sends a guest to the login page and keeps the full authorize URL as intended" (password and passkey login are the product's) |
| S43 | Consent asked every time | covered | `Isolated/AuthorizeConsentRouteTest` "asks for consent every time", "never skips consent, even when the product client model would" |
| S44 | Page shows self-asserted name, return host, grantable options | covered | `Isolated/AuthorizeConsentRouteTest` "renders the consent page with the client as self-asserted, the return host and the options" |
| S45 | Approval needs a pending request for the same user | covered | `Isolated/AuthorizeConsentRouteTest` "refuses an approval without the pending request it was rendered for", "consumes the pending request" |
| S46 | Approval checked as an act: only grantable offered values | covered | `Isolated/AuthorizeConsentRouteTest` "judges the posted choices against the offered options, never the form", "refuses an approval when the user may not grant anything" |
| S47 | Silence never means "all"; at least one MCP scope | covered | `Isolated/AuthorizeConsentRouteTest` "approves with every resource only when the user says so explicitly" |
| S48 | The grant holds what the user approved | covered | `Isolated/AuthorizeConsentRouteTest` "approves: narrowed grant, consent record, event" |
| S49 | Super-admin role rules | product | `ConsentProvider` |
| S50 | Deny sends `access_denied` | covered | `Isolated/AuthorizeConsentRouteTest` "denies: access_denied with state and iss…". A denial is recorded (90 days), per standards decision 5, which supersedes "records nothing" |
| S51 | An Inertia approve leaves with a full-page redirect | covered | `Isolated/AuthorizeConsentRouteTest` "leaves an Inertia approval with a full-page location"; `Unit/Services/AuthorizationResponseServiceTest` |
| S52 | Re-consent: new grant; old one and its tokens and codes revoked | covered | `Isolated/AuthorizeConsentRouteTest` "revokes the earlier codes and tokens of the same client and user on a new consent" |
| S53 | Old refresh token after re-consent does not revoke the new grant | covered | `Isolated/FamilyRevokingRefreshTokenRepositoryTest` "does not revoke a newer grant…"; `Isolated/RevocationRouteTest` "never revokes a newer consent" |
| S54 | Token minted for a grant revoked before the exchange revoked at once | covered | `Isolated/TokenEndpointRouteTest` "revokes at once a token minted for a grant revoked before the exchange" |
| S55 | A grant row never authenticates as an API key | product | `ApiKeyDoor` |
| S56 | Atomic rotation; reuse revokes the family | covered | `Isolated/TokenEndpointRouteTest` "revokes the family and the grant when a used refresh token comes back"; `Isolated/FamilyRevokingRefreshTokenRepositoryTest`; `Http/RealHttpFlowTest` step 4 |
| S57 | Parallel refresh from two processes: at most one usable pair | covered | `Http/RealHttpFlowTest` "S57" (two `php -S` processes; SQLite, PostgreSQL, MySQL, MariaDB) |
| S58 | A purged refresh token is refused | covered | `Isolated/FamilyRevokingRefreshTokenRepositoryTest` "treats a missing refresh token as revoked" |
| S59 | Refresh refused without an active bound grant | covered | `Isolated/FamilyRevokingRefreshTokenRepositoryTest` S59 tests |
| S60 | Expired, revoked, garbage: `invalid_token`, distinct descriptions | covered | `Isolated/McpDoorRouteTest` "refuses a token with a description that says why" |
| S61 | Wrong or no audience refused | covered | `Isolated/McpDoorRouteTest` (another audience, no audience) |
| S62 | Revoked client refused on the next call | covered | `Isolated/McpDoorRouteTest` (a revoked client) |
| S63 | Unbound or other-grant tokens refused | covered | `Isolated/McpDoorRouteTest` (no binding, bound to another grant) |
| S64 | Wire scopes exactly `[mcp:use]` | covered | `Isolated/McpDoorRouteTest` "judges the wire scopes as a set", scopes other than `mcp:use`, no or null `scopes` claim |
| S65 | Revoked grant refuses its tokens with live token rows | covered | `Isolated/McpDoorRouteTest` (a revoked grant, token row untouched) |
| S66 | Grant without the product's MCP scope: 403 naming it | covered | `Isolated/McpDoorRouteTest` "renders the product's refusal: 403 insufficient_scope or 401 invalid_token" (the decision is the product's `GrantAuthorizer`) |
| S67 | Owner deactivation revokes grants | product | `GrantAuthorizer`, `GrantStore` |
| S68 | Demoted owner loses access on the next call | product | `GrantAuthorizer` |
| S69 | externa 1.x: plain `mcp:read` key keeps working | product | `ApiKeyDoor` |
| S70 | Bare challenge; RFC 6750 codes survive; `resource_metadata` when on | covered | `Isolated/McpDoorRouteTest` "asks for credentials with the resource metadata and the scope, without an error code", "renders the product's refusal"; `Http/RealHttpFlowTest` step 3 |
| S71 | API keys keep their wording when OAuth is on | covered | `Isolated/McpDoorRouteTest` "keeps API keys working with OAuth on", "names insufficient_scope when the product refuses an API key with 403" |
| S72 | Both doors bind identically | product | `McpCredentialBinder` |
| S73 | `/mcp` outside `web`: a session cookie never authenticates | covered | `Isolated/McpDoorRouteTest` "refuses a signed-in browser session without a Bearer, even on a route inside web" (a control route proves the session is live) |
| S74 | Failure brake 429 before the per-key throttle | covered | `Isolated/McpDoorRouteTest` "answers 429 before reading the credential once an address has failed too often" |
| S75 | Connected apps lists only the user's own active grants | covered | `Isolated/ConnectedAppsTest` (API keys are the product's) |
| S76 | A user revoke refuses the next call and refresh, and revokes unexchanged codes | covered (#49) | `Isolated/ConnectedAppsTest`: the grant, its access and refresh tokens, and the codes it issued (codes issued before the revoke, while no newer grant is active); a newer consent's code and a code issued during the revoke survive |
| S77 | Revoke after losing AI access, and while OAuth is off | covered | `Isolated/ConnectedAppsTest` "lists … with OAuth off too" (losing access is the product's) |
| S78 | Audit entries name client and redirect host | product | `AuditLogger`; the events carry the ids and hosts (`Unit/Events/McpEventsCarryUuidsOnlyTest`) |
| S79 | Token material never in logs, exceptions, events, audit | covered | `Isolated/SecretsStayOutOfLogsTest` (every log line and package event across exchange, rotation, reuse, replay and revocation); `Unit/Events/McpEventsCarryUuidsOnlyTest`; token error bodies are fixed strings (`Unit/Services/TokenErrorResponseServiceTest`) |
| S80 | No bigint in contracts, events, route keys, props | covered | `Unit/Data/GrantRecordTest`; `Unit/Events/McpEventsCarryUuidsOnlyTest`; admin and settings routes use UUIDs and `public_id` |
| S81 | Without Inertia boots; enabled without a `ConsentView` fails clearly | covered | `Feature/AdapterBootTest` |

## Open items

- **First approval against the unused-client prune (from the review of #45): closed by #54.** The approval now holds the client's metadata row lock, the one the prune takes before deleting: a prune that commits first leaves the approval refused, and an approval that commits first keeps the client. `Isolated/FirstApprovalPruneRaceTest` covers both orders with two database sessions on PostgreSQL, MySQL and MariaDB.
