# 2026-11-20: Every product is the authorization server of its own /mcp

**Decided by:** the maintainer, after two independent reviews.

**Decision.** Each product is the OAuth authorization server of its own `/mcp`, built on Passport and `laravel/mcp` as Laravel ships them. The package follows `laravel/mcp`'s wire contract (`Mcp::oauthRoutes()` paths, the `mcp:use` scope) and wraps only what those cannot express. A central authorization server whose JWTs every product validates is dropped from the plan.

**Why.** Staying on what Laravel ships keeps every product upgradable with the framework. Self-hosted single-product installs keep working without a separate identity service. API keys and OAuth grants share the product's entitlement rows and one authorizer: the dangerous divergence is two authorisation logics, not two vocabularies of scope strings.

**Consequences.** Passport's own routes are never registered (S4); its tables stay as Passport publishes them, and the package keeps its own state in side tables.
