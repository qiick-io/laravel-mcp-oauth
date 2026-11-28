# Consent page interface

The package renders the OAuth consent screen for `GET /oauth/authorize` and
handles the decision on `POST` (approve) and `DELETE` (deny) of the same path.
The page component itself belongs to the app-ui registry (decision
2026-11-22); this file is the contract that component implements.

## How the page is rendered

1. `ValidateAuthorizationRequestMiddleware` has already checked PKCE `S256`,
   `resource`, the client, the blocked hosts and the exact `redirect_uri`.
   Every refusal before this point is a JSON 400, never a redirect.
2. A guest is sent to the `login` route; the full authorize URL is kept as the
   intended URL, so the user comes back here after password or passkey login.
3. `ConsentPageService` asks the product's `ConsentProvider::options()` what
   this user may grant this client, builds a `ConsentPage` and passes it to the
   bound `ConsentView`.
4. With `inertiajs/inertia-laravel` installed the default view is
   `InertiaConsentView`, which renders the Inertia page **`oauth/authorize`**.
   A product without Inertia binds its own `ConsentView`.

The page is shown on every authorization: a grant narrows scopes, role and
resources, and only the user can choose that again. It is served with
`X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.

## Props

The props mirror `Qiick\McpOAuth\Data\ConsentPage` one to one. As TypeScript:

```ts
interface ConsentOption {
    value: string;
    label: string;
    /** false: show it, disabled, so the user sees what they cannot give */
    grantable: boolean;
    description: string | null;
}

interface OAuthAuthorizePageProps {
    client: {
        id: string; // Passport client UUID
        /** Show the name as a claim whenever nameIsSelfAsserted is true */
        name: string;
        /** The host the grant returns to (or the scheme of a private-use URI) */
        redirectHost: string;
        nameIsSelfAsserted: boolean;
        /** Present for first-party Companion clients enrolled by the server */
        operatorName?: string;
        /**
         * The callback this request returns to is loopback http (127.0.0.1,
         * localhost, [::1]): warn that the code goes to a program on this
         * computer, whichever program listens on that port (S3). A caution,
         * not evidence of the app's identity: keep showing the return host
         * and the self-asserted name.
         */
        isRedirectLoopback: boolean;
    };
    /** Must be posted back as `auth_token` */
    authToken: string;
    /**
     * The Advanced section, closed by default: the client id, registration
     * source, the requested protocol resources, the callback this approval returns to, then what
     * the client registered (callbacks, website, terms, privacy policy,
     * contacts, software), each row only when it has a value. The registered
     * fields are the client's own claim.
     */
    advanced: { label: string; value: string }[];
    /** Present when consent covers an additional RFC 8707 resource. */
    resourceScopes?: Record<string, string>;
    /** Present for a consent that authorizes pairing with this installation. */
    isInstallationPairing?: true;
    options: {
        scopes: ConsentOption[];
        /** Empty: the product has no role choice; post no `role` */
        roles: ConsentOption[];
        /** Collections, areas, …; may be empty */
        resources: ConsentOption[];
        /** More than one: the user must pick one (instituta); one: preselected; none: hidden */
        organisations: ConsentOption[];
        /** true: at least one resource, or an explicit "all resources" */
        resourcesRequired: boolean;
        /** false: explain why and offer only "Deny" */
        canGrant: boolean;
        notices: string[];
    };
}
```

What the page must show:

- the client name and `redirectHost` prominently alongside it. When
  `nameIsSelfAsserted` is true, label the name as the client's own claim.
  For a first-party client, display its `operatorName`;
- the scopes, roles, resources and organisations, with non-grantable options
  visible but disabled;
- each requested protocol resource in `resourceScopes`, which is independent
  of the product permissions in `options.resources`;
- every entry of `notices`.

When `isInstallationPairing` is true, display “Pair this phone”. The
authorization request's installation id and key thumbprint stay in the
server session and travel to the grant without being posted by the form.

For registered resources, the append-only record captures the entire displayed
map in `oauth_consent_records.resource_scopes` for either decision.
`McpConsentApprovedEvent::resourceScopes` carries the same approved pairs.

## Form

Both actions post to the same URL, `/oauth/authorize` (route names
`passport.authorizations.approve` and `passport.authorizations.deny`), behind
`web`, `auth` and `verified`. With Inertia, the XSRF cookie covers CSRF; a
plain HTML form must include `_token`.

What the package does not decide, and the product must:

- **Deactivated accounts.** The package checks only `auth` and `verified`.
  A user who may sign in but must not connect apps gets `canGrant: false` from
  `ConsentProvider::options()`, or is stopped by middleware the product appends
  to its `web` group (the same goes for enforcing two-factor enrolment).
- **Email verification.** `verified` sends an unverified browser approval to
  the `verification.notice` route; without that route the request is a 500.
  A request that expects JSON gets a 403 instead.
- **`prompt`.** `none` and `consent` are honoured; `login` is ignored, because
  Passport would sign the user out on a plain GET.

Approve, `POST /oauth/authorize`:

| Field | Type | Rule |
| --- | --- | --- |
| `auth_token` | string | the `authToken` prop; anything else is a 403 |
| `scopes[]` | list of strings | at least one; each offered and grantable |
| `role` | string | required and grantable when `roles` is not empty; refused when it is |
| `resources[]` | list of strings | each offered and grantable |
| `all_resources` | boolean | explicit "every resource"; `resources[]` is then ignored |
| `organisation` | string | required with two or more organisations; must be offered and grantable |

Errors come back as normal Laravel validation errors (422, or the Inertia
error bag) on those field names; the pending request stays in the session, so
the user can correct and post again. The product's `ConsentProvider::validate()`
runs after these checks and may add its own field errors.

Deny, `DELETE /oauth/authorize` with `auth_token` only.

Both answer with a redirect to the client: the code (approve) or
`error=access_denied` (deny), with `state` and `iss`. An Inertia visit gets a
409 with `X-Inertia-Location`, so the browser leaves with a full page load.

An approval posted after `ConsentOptions::$consentVersion` changed (a deploy
or a policy change since the page was shown) answers 409 without a location
and drops the pending request: the user must start again and see the current
text before it is recorded as accepted.

## Evidence

Every decision writes one row in `oauth_consent_records`, with the consent
version, locale and resource of the page the user saw (stored in the session
when it was rendered): `approved` with the new grant id, or `denied` with `retention_until` set 90 days ahead
(`revoked_retention_days`). Approve also dispatches `McpConsentApprovedEvent`, deny
`McpConsentDeniedEvent`.
