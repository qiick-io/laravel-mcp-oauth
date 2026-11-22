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
        /** The client's own claim: always show it as such */
        name: string;
        /** The host the grant returns to (or the scheme of a private-use URI) */
        redirectHost: string;
        nameIsSelfAsserted: true;
    };
    /** Must be posted back as `auth_token` */
    authToken: string;
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

- the client name, marked as the client's own claim (for example "Cursor
  (name chosen by the app)"), and `redirectHost` next to it, prominently: the
  host is the fact, the name is not;
- the scopes, roles, resources and organisations, with non-grantable options
  visible but disabled;
- every entry of `notices`.

## Form

Both actions post to the same URL, `/oauth/authorize` (route names
`passport.authorizations.approve` and `passport.authorizations.deny`), behind
`web`, `auth` and `verified`. With Inertia, the XSRF cookie covers CSRF; a
plain HTML form must include `_token`.

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

## Evidence

Every decision writes one row in `oauth_consent_records`: `approved` with the
new grant id, or `denied` with `retention_until` set 90 days ahead
(`revoked_retention_days`). Approve also dispatches `McpConsentApproved`, deny
`McpConsentDenied`.
