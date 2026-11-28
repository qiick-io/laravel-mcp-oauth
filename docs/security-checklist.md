# Security checklist: design scenarios S1–S81 and the tests that cover them

Each scenario of the design's test table (§11, `projects/qiick/packages/laravel-mcp-oauth-design.md` in the knowledge base) names the test that fails when the property breaks, so the 1.0 checklist ("every security item has a red-first test that names it") can be checked line by line. The S-numbers here are the design's. Some test titles carry the standards review's own S-numbers (`S2: CIMD runtime…`), which are a different list.

Status:

- **Covered**: package tests prove it;
- **Partial**: the package side is proved, part of the scenario is not;
- **Product**: the scenario lives behind a product adapter (`ConsentProvider`, `GrantAuthorizer`, `ApiKeyDoor`, `McpCredentialBinder`, `AuditLogger`) and belongs in the product's suite;
- **Gap**: not proved yet.

Paths are under `tests/`; `Http/RealHttpFlowTest` runs over real HTTP (`php -S`) on all four database engines.

| # | Property | Covering test | Status |
| --- | --- | --- | --- |
| S1 | Any gate off: every OAuth and discovery route 404 | `Isolated/DiscoveryRouteTest` "with OAuth off answers every discovery document like a missing route"; the "with OAuth off matches an unregistered …" tests in `Isolated/DcrRegisterRouteTest`, `TokenEndpointRouteTest`, `RevocationRouteTest`, `AuthorizeConsentRouteTest`; `Unit/Http/EnsureMcpOAuthEnabledMiddlewareTest` | Covered |
| S2 | Admin switch off while config is on: 404 | `Unit/McpOAuthServerTest` "is off unless config, admin switch and product MCP flag are all true"; `Http/RealHttpFlowTest` step 6 (admin switch) | Covered |
| S3 | MCP off with OAuth on: OAuth routes and `/mcp` 404 | OAuth routes: `Unit/McpOAuthServerTest` (product MCP flag gate). `/mcp` is the product's route | Partial |
| S4 | Passport's own routes never registered | `Feature/PassportBootTest` "always ignores Passport routes"; `Isolated/PassportRoutesAbsentTest` | Covered |
| S5 | Off: `/mcp` challenge unchanged, no metadata link | `Isolated/McpDoorRouteTest` "with OAuth off keeps the plain challenge and the API-key door"; `Isolated/DiscoveryRouteTest` "leaves the /mcp challenge of laravel/mcp as if the package were absent" | Covered |
| S6 | Off: non-key Bearer is an unknown API key; API keys work | `Isolated/McpDoorRouteTest` "with OAuth off takes any Bearer the product accepts"; `Http/RealHttpFlowTest` step 6 | Covered |
| S7 | Keys missing: OAuth routes 503; HTML 503 for a browser authorize | `Isolated/AuthorizeConsentRouteTest` "answers a browser 503 page and a JSON 503"; the 503 tests in `DcrRegisterRouteTest` and `TokenEndpointRouteTest`; `Http/RealHttpFlowTest` step 7 | Covered |
| S8 | Keys missing: non-key Bearer 503 on `/mcp`; API key still works | `Isolated/McpDoorRouteTest` "answers 503 for an OAuth token while the keys are missing"; `Http/RealHttpFlowTest` step 7 | Covered |
| S9 | Half-set env key pair counts as missing | `Unit/McpOAuthServerTest` "treats a half-set env key pair as missing"; `Unit/McpOAuthServerMutationTest`; `Isolated/RetentionCommandsTest` "reports an incomplete env key pair" | Covered |
| S10 | World-readable key file counts as missing (503) | `Unit/McpOAuthServerTest` "treats world-readable key files as missing"; `Unit/McpOAuthServerMutationTest` mode tests | Covered |
| S11 | Switch refuses to turn on without keys; unreadable store is off | `Isolated/SwitchMcpOAuthTest`; `Unit/McpOAuthServerTest` "treats an unreadable admin switch store as off", "treats a throwing admin switch as off" | Covered |
| S12 | Readiness reports `passport_keys` only while enabled | `Unit/McpOAuthServerTest` "reports passport_keys only while OAuth is enabled" | Covered |
| S13 | Issuer, resource and endpoints from `APP_URL`; `mcp.authorization_server` pinned | `Isolated/DiscoveryRouteTest` "builds every URL from APP_URL, never from the Host header"; `Http/RealHttpFlowTest` step 1; `Feature/ServiceProviderTest` "pins laravel/mcp's authorization server to the issuer, unless the product set one" | Covered |
| S14 | Root and nested discovery shadow laravel/mcp's | `Isolated/DiscoveryRouteTest` "publishes … root and nested", "serves the nested authorization server document only for the MCP path" | Covered |
| S15 | Metadata advertises only `mcp:use`, `code`, the two grants, `S256` | `Isolated/DiscoveryRouteTest` (exact JSON); `Unit/McpOAuthServerTest` "builds the RFC 8414 and RFC 9728 documents" | Covered |
| S16 | `resource` required and exact at authorize and token | `Isolated/TokenEndpointRouteTest` "requires the resource to name this MCP endpoint on both grants"; `Unit/McpOAuthServerTest` "compares the resource path exactly" | Covered |
| S17 | PKCE `S256` only; a JSON 400, never a redirect | `Isolated/AuthorizeConsentRouteTest` "refuses an authorization request without PKCE S256 as JSON, never a redirect" | Covered |
| S18 | Code exchange without the verifier refused | `Isolated/TokenEndpointRouteTest` "refuses a code exchange without the PKCE verifier" | Covered |
| S19 | Only `authorization_code` and `refresh_token`; device grant off | `Isolated/TokenEndpointRouteTest` "accepts only the authorization code and refresh token grants", "refuses the password grant"; `Feature/PassportBootTest` device grant; `Isolated/PassportAuthCodeTtlTest` "keeps only the MCP grants" | Covered |
| S20 | Foreign wire scopes dropped; tokens carry only `mcp:use` | `Isolated/AuthorizeConsentRouteTest` "drops foreign wire scopes"; `Isolated/TokenEndpointRouteTest` "exchanges a code for a bound token pair that names the wire scope"; `Feature/PassportScopeBootTest` | Covered |
| S21 | Token response names `scope=mcp:use` | `Unit/McpBearerTokenResponseTest`; `Isolated/TokenEndpointRouteTest` | Covered |
| S22 | Fragments and dangerous schemes refused, even when listed | `Unit/RedirectUriGuardTest` "refuses fragments and dangerous schemes even when listed as custom"; `Unit/RedirectUriGuardAdversarialTest` | Covered |
| S23 | `https`, loopback `http`, listed schemes accepted; other `http` refused | `Unit/RedirectUriGuardTest` "accepts https and loopback http including IPv6"; `Unit/RedirectUriGuardCanonicalParseTest` N1; `Http/RealHttpFlowTest` step 2 | Covered |
| S24 | `http://[::1]` completes the whole flow | `Http/RealHttpFlowTest` "runs the whole flow to tools/list with an IPv6 loopback callback" | Covered |
| S25 | Non-ASCII registered hosts refused | `Unit/RedirectUriGuardTest` "refuses non-ASCII registered hosts"; `Unit/RedirectUriGuardAdversarialTest` | Covered |
| S26 | League `UriString` only; no `parse_url` in `src/` | `Arch/PackageArchitectureTest` "src never calls parse_url"; `Unit/RedirectUriGuardAdversarialTest` "forbids parse_url anywhere under src" | Covered |
| S27 | Per-address registration limit | `Isolated/DcrRegisterRouteTest` "limits unauthenticated registrations per address with Retry-After"; `Feature/RateLimiterBootTest` | Covered |
| S28 | Global cap answers 503 | `Isolated/DcrRegisterRouteTest` "answers 503 when the global client cap is reached" | Covered |
| S29 | Throttle keys unmap `::ffff:`, `::a.b.c.d`, `64:ff9b::`; IPv6 by /64 | `Unit/ClientThrottleKeyTest` | Covered |
| S30 | Throttle IP is `Request::ip()`; untrusted `X-Forwarded-For` ignored | `Unit/ClientThrottleKeyTest` "ignores X-Forwarded-For when proxies are not trusted" | Covered |
| S31 | Prune: unused clients past retention; keeps ever-authorised and fresh ones | `Isolated/RetentionCommandsTest` prune tests, the 23/24/25-hour boundary, B1 (grant purged) and M1 (authorised during the prune) | Covered |
| S32 | DCR refuses a blocked host | `Isolated/DcrRegisterRouteTest` "refuses registration for a blocked redirect host" | Covered |
| S33 | Admin Unicode host stored as ASCII; invalid IDNA refused | `Isolated/AdminBlockActionsTest` "blocks a host and its subdomains, normalised to ASCII", "refuses a host that does not normalise"; `Unit/RedirectUriGuardTest` | Covered |
| S34 | The NFC punycode form of a blocked IDN refused | `Isolated/DcrRegisterRouteTest` "refuses the punycode of an IDN an admin blocked in Unicode, composed or not" (allowed before the block) | Covered |
| S35 | Exact or subdomain match; `notapp.test` ≠ `app.test` | `Unit/RedirectUriGuardTest` "blocks exact hosts and subdomains but not sibling suffixes" | Covered |
| S36 | A host that does not normalise counts as blocked | `Unit/RedirectUriGuardTest` "treats a host that does not normalise as blocked" | Covered |
| S37 | Existing clients refused at authorize, token and `/mcp` after a block | `Isolated/AuthorizeConsentRouteTest`, `TokenEndpointRouteTest`, `McpDoorRouteTest` (blocked host); `Http/RealHttpFlowTest` step 5 | Covered |
| S38 | Token-endpoint block check reads the client id from HTTP Basic | `Isolated/TokenEndpointRouteTest` "refuses a client whose redirect host was blocked, by body or HTTP Basic client_id" | Covered |
| S39 | Host block: short transaction, chunked revocation outside it | `Isolated/AdminBlockActionsTest` "blocks every matching client across more than one chunk", "blocks a host without one transaction around the client walk" (one transaction per blocked client, never nested) | Covered |
| S40 | Bulk block: 1–100 distinct ids, each fully revoked | `Isolated/AdminBlockActionsTest` bulk test and the 422 matrix | Covered |
| S41 | Blocking a client revokes it and every credential | `Isolated/AdminBlockActionsTest` "blocks a client: revokes it, its grants, tokens and codes"; refusal of a revoked client in `McpDoorRouteTest`, `TokenEndpointRouteTest`, `AuthorizeConsentRouteTest` | Covered |
| S42 | A guest goes to login; the authorize query survives login | `Isolated/AuthorizeConsentRouteTest` "sends a guest to the login page and keeps the full authorize URL as intended" (password and passkey login are the product's) | Covered |
| S43 | Consent asked every time | `Isolated/AuthorizeConsentRouteTest` "asks for consent every time", "never skips consent, even when the product client model would" | Covered |
| S44 | Page shows self-asserted name, return host, grantable options | `Isolated/AuthorizeConsentRouteTest` "renders the consent page with the client as self-asserted, the return host and the options" | Covered |
| S45 | Approval needs a pending request for the same user | `Isolated/AuthorizeConsentRouteTest` "refuses an approval without the pending request it was rendered for", "consumes the pending request" | Covered |
| S46 | Approval checked as an act: only grantable offered values | `Isolated/AuthorizeConsentRouteTest` "judges the posted choices against the offered options, never the form", "refuses an approval when the user may not grant anything" | Covered |
| S47 | Silence never means "all"; at least one MCP scope | `Isolated/AuthorizeConsentRouteTest` "approves with every resource only when the user says so explicitly" | Covered |
| S48 | The grant holds what the user approved | `Isolated/AuthorizeConsentRouteTest` "approves: narrowed grant, consent record, event" | Covered |
| S49 | Super-admin role rules | `ConsentProvider` | Product |
| S50 | Deny sends `access_denied` | `Isolated/AuthorizeConsentRouteTest` "denies: access_denied with state and iss…". A denial is recorded (90 days), per standards decision 5, which supersedes "records nothing" | Covered |
| S51 | An Inertia approve leaves with a full-page redirect | `Isolated/AuthorizeConsentRouteTest` "leaves an Inertia approval with a full-page location"; `Unit/Services/AuthorizationResponseServiceTest` | Covered |
| S52 | Re-consent: new grant; old one and its tokens and codes revoked | `Isolated/AuthorizeConsentRouteTest` "revokes the earlier codes and tokens of the same client and user on a new consent" | Covered |
| S53 | Old refresh token after re-consent does not revoke the new grant | `Isolated/FamilyRevokingRefreshTokenRepositoryTest` "does not revoke a newer grant…"; `Isolated/RevocationRouteTest` "never revokes a newer consent" | Covered |
| S54 | Token minted for a grant revoked before the exchange revoked at once | `Isolated/TokenEndpointRouteTest` "revokes at once a token minted for a grant revoked before the exchange" | Covered |
| S55 | A grant row never authenticates as an API key | `ApiKeyDoor` | Product |
| S56 | Atomic rotation; reuse revokes the family | `Isolated/TokenEndpointRouteTest` "revokes the family and the grant when a used refresh token comes back"; `Isolated/FamilyRevokingRefreshTokenRepositoryTest`; `Http/RealHttpFlowTest` step 4 | Covered |
| S57 | Parallel refresh from two processes: at most one usable pair | `Http/RealHttpFlowTest` "S57" (two `php -S` processes; SQLite, PostgreSQL, MySQL, MariaDB) | Covered |
| S58 | A purged refresh token is refused | `Isolated/FamilyRevokingRefreshTokenRepositoryTest` "treats a missing refresh token as revoked" | Covered |
| S59 | Refresh refused without an active bound grant | `Isolated/FamilyRevokingRefreshTokenRepositoryTest` S59 tests | Covered |
| S60 | Expired, revoked, garbage: `invalid_token`, distinct descriptions | `Isolated/McpDoorRouteTest` "refuses a token with a description that says why" | Covered |
| S61 | Wrong or no audience refused | `Isolated/McpDoorRouteTest` (another audience, no audience) | Covered |
| S62 | Revoked client refused on the next call | `Isolated/McpDoorRouteTest` (a revoked client) | Covered |
| S63 | Unbound or other-grant tokens refused | `Isolated/McpDoorRouteTest` (no binding, bound to another grant) | Covered |
| S64 | Wire scopes exactly `[mcp:use]` | `Isolated/McpDoorRouteTest` "judges the wire scopes as a set", scopes other than `mcp:use`, no or null `scopes` claim | Covered |
| S65 | Revoked grant refuses its tokens with live token rows | `Isolated/McpDoorRouteTest` (a revoked grant, token row untouched) | Covered |
| S66 | Grant without the product's MCP scope: 403 naming it | `Isolated/McpDoorRouteTest` "renders the product's refusal: 403 insufficient_scope or 401 invalid_token" (the decision is the product's `GrantAuthorizer`) | Covered |
| S67 | Owner deactivation revokes grants | `GrantAuthorizer`, `GrantStore` | Product |
| S68 | Demoted owner loses access on the next call | `GrantAuthorizer` | Product |
| S69 | externa 1.x: plain `mcp:read` key keeps working | `ApiKeyDoor` | Product |
| S70 | Bare challenge; RFC 6750 codes survive; `resource_metadata` when on | `Isolated/McpDoorRouteTest` "asks for credentials with the resource metadata and the scope, without an error code", "renders the product's refusal"; `Http/RealHttpFlowTest` step 3 | Covered |
| S71 | API keys keep their wording when OAuth is on | `Isolated/McpDoorRouteTest` "keeps API keys working with OAuth on", "names insufficient_scope when the product refuses an API key with 403" | Covered |
| S72 | Both doors bind identically | `McpCredentialBinder` | Product |
| S73 | `/mcp` outside `web`: a session cookie never authenticates | `Isolated/McpDoorRouteTest` "refuses a signed-in browser session without a Bearer, even on a route inside web" (a control route proves the session is live) | Covered |
| S74 | Failure brake 429 before the per-key throttle | `Isolated/McpDoorRouteTest` "answers 429 before reading the credential once an address has failed too often" | Covered |
| S75 | Connected apps lists only the user's own active grants | `Isolated/ConnectedAppsTest` (API keys are the product's) | Covered |
| S76 | A user revoke refuses the next call and refresh, and revokes unexchanged codes | `Isolated/ConnectedAppsTest`: the grant, its access and refresh tokens, and the codes it issued (codes issued before the revoke, while no newer grant is active); a newer consent's code and a code issued during the revoke survive | Covered |
| S77 | Revoke after losing AI access, and while OAuth is off | `Isolated/ConnectedAppsTest` "lists … with OAuth off too" (losing access is the product's) | Covered |
| S78 | Audit entries name client and redirect host | `Isolated/AuditTrailTest` (every entry, its host and its failure semantics; mapping in `docs/audit.md`); the events carry the ids and hosts (`Unit/Events/McpEventsCarryUuidsOnlyTest`) | Covered |
| S79 | Token material never in logs, exceptions, events, audit | `Isolated/SecretsStayOutOfLogsTest` (every log line and package event across exchange, rotation, reuse, replay and revocation); `Unit/Events/McpEventsCarryUuidsOnlyTest`; token error bodies are fixed strings (`Unit/Services/TokenErrorResponseServiceTest`) | Covered |
| S80 | No bigint in contracts, events, route keys, props | `Unit/Data/GrantRecordTest`; `Unit/Events/McpEventsCarryUuidsOnlyTest`; admin and settings routes use UUIDs and `public_id` | Covered |
| S81 | Without Inertia boots; enabled without a `ConsentView` fails clearly | `Feature/AdapterBootTest` | Covered |

## CIMD (standards review S2)

`Isolated/ClientMetadataDocumentsTest` covers truthful discovery, exact URL
identity, the public client lifecycle, configured callback domains, and
revalidation before consent. `Unit/OutboundClientMetadataDocumentFetcherTest`
checks a changed DNS answer, no redirect following and conditional requests.
`Http/RealHttpFlowTest` exercises the CIMD login and token lifecycle over HTTP
with a deterministic outbound transport fixture.

## Additional protected resources (Companion CMP3 and CMP4)

The CMP3 flows in `Http/RealHttpFlowTest` prove the browser returns with
both resource indicators, the user sees both audiences, each token has one
approved scope, and rotation retires only the selected audience's token.
The race uses two PHP processes and independent database connections,
including on PostgreSQL and MySQL. Reuse makes every issued credential
unusable. `Isolated/RegisteredResourcesTest` covers the stored audience
and scope, immutable grant pairs and rejection of ambiguous fields.

CMP4 exercises real DCR and fetched CIMD identities, a browser session and
an API key against the restricted resource. The test fixture assigns the
trusted Companion class during setup. The product's live principal and
organisation checks run through `GrantAuthorizer` and are exercised by
changing its decision between HTTP requests.

## First-party Companion identity and issuer (MO4)

`Isolated/PreRegisteredCompanionClientTest` proves the shipped callback policy,
reservation from dynamic and fetched registrations, refusal while disabled,
and issuer equality on approval and denial. The fixture requires no network
access for the reserved identifier.

## Open items

None.

## Closed since the first pass

- **First approval against the unused-client prune (from the review of #45): closed.** The approval now holds the client's metadata row lock, the one the prune takes before deleting: a prune that commits first leaves the approval refused, and an approval that commits first keeps the client. `Isolated/FirstApprovalPruneRaceTest` covers both orders with two database sessions on PostgreSQL, MySQL and MariaDB.
