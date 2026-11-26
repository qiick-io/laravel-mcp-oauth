# 2026-11-23: What an RFC 7009 revocation revokes

**Decided by:** the team lead, under the maintainer's rule to take the standard and secure option.

**Decision.**

- **A refresh token:** every access and refresh token of its family, and the product grant, with `RevocationReason::Client`. RFC 7009 §2.1 says the server should invalidate the tokens based on the same grant, and a grant with no usable credential is dead anyway.
- **An access token:** that token and the refresh tokens issued with it (RFC 7009 §2.1 allows it); the grant stays.
- Refresh tokens invalidated this way are **deleted, not marked revoked**: a later presentation is unknown (S58) and is never read as reuse, so a client's own revocation never triggers a theft signal.
- A valid, authenticated request always gets an empty 200, also for an unknown, expired or foreign token (RFC 7009 §2.2), so the endpoint is not a token oracle. A malformed request is still a 400 and failed client authentication a 401 (RFC 7009 §2.2.1).

**Why.** It amends the standards review's resolution of the same question (Resolved #5), which kept the refresh token on an access-token revocation.
