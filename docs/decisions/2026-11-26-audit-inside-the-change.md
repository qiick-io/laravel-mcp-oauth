# 2026-11-26: Audit entries are written inside their change

**Decided by:** the maintainer, approving the fixes made for the security review of the audit trail.

**Decision.**

- `AuditLogger::record()` runs inside the database transaction of the change it describes, before the change's event. A sink that throws rolls the change back, no event is dispatched, and the caller can retry from a clean state.
- A grant revoke writes the product's `GrantStore` last, after the token changes and the entry, holding the Passport client's row lock: two concurrent revokes of one grant record one entry.
- If Passport's transaction fails after a `GrantStore` on another connection has committed, the revoke completes forward: the tokens and the entry are written again and the failure is reported. A revoked grant is never un-revoked.

**Why.** A security change must never be committed without its audit entry; this is also how the 1.5 activity log in Externa was written. The alternative, a sink that may fail silently, would leave admin and consent changes unaudited.

**Consequences.** A broken product sink now blocks the change instead of being skipped. `docs/audit.md` documents the entries, their transactions and the mapping onto the 1.5 activity log names.
