# 2026-11-22: One shared MCP OAuth package, off by default

**Decided by:** the maintainer.

**Decision.**

- Every product ships the same MCP OAuth core from this package, installed but **off by default**. An admin switches it on, and the switch lives in each product's own settings store (`AdminSwitch`). API keys stay on either way.
- The package depends on interfaces only (`GrantStore`, `ConsentProvider`, `GrantAuthorizer`, …); each product keeps its own entitlement model and maps `mcp:use` onto its grant.
- Revoked clients and grants are kept 90 days for audit, then deleted (`revoked_retention_days`, the prune and purge commands).
- A denial writes one `denied` consent record, kept 90 days, so a refused phishing attempt leaves evidence; it changes no grant or credential (S50).
- With several organisations the consent screen asks which one the grant belongs to; with exactly one it is used without asking.

**Why.** The products had copies of the same security code (Unicode host-block bypass, refresh-token reuse, stale tokens after re-consent), and copies drift. OAuth is off by default because of attack surface, not complexity: with it on, dynamic client registration is a public endpoint and Passport keys must exist.
