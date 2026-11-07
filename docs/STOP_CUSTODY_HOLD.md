# Resident STOP boundary: source-only candidate, not installed

An explicit local synthetic grant previously survived a restored pre-STOP
SQLite snapshot. `LocalHandoffGate` now requires a separately governed STOP
admission for **both** grant and file export, held through the final atomic
publication; old grants and resident database snapshots cannot substitute.

The default has **no independent authority configured**, so local grant/export
fails closed. Existing tests must inject an isolated *test-only* provider to
exercise positive local handoff behavior. Do not bind the synthetic provider
in production.

An authorized host-owned implementation must provide one monotonic STOP state
and cross-process lock over `hold_active()` and `revoke()`, protected from
resident/model write identities, with negative tests for snapshots, crashes,
restarts, witness outages and effective ACLs. This protection is **not**
demonstrated by these source tests, hashes or in-memory locks.

No phone transport exists here, and this candidate authorizes no contact.
Release remains `HOST_CUSTODY_HOLD / CONTACT_HOLD`. See `REPORT.md` for
reproduction, exact heads, 25/25 local tests and 6/6 independent tests,
including an explicit negative test of lost STOP-witness history.
