# 2026-11-26: Event names end with Event

**Decided by:** the maintainer.

**Decision.** Every package event is renamed `<Subject><PastTenseVerb>Event` before the beta, as fleet convention F5 requires; the one name without a verb gains one (`McpPassportKeysFoundMissingEvent`). `UPGRADING.md` maps every old name to its new one. No divergence entry is kept.

**Why.** The fleet standardises on one event naming style, and the rename is free now: no product listens to these events yet, and after the beta it would be a break for every adopter.

**Consequences.** `UPGRADING.md` lists every old and new name. The audit entry names (`oauth_consent_approved`, …) and the events' constructor arguments are unchanged.
