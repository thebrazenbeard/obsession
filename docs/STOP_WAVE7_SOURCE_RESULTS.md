# Wave 7 — Resident adapter for protected STOP custodian (SOURCE ONLY)

Date: 2026-11-07. Source anchor: `thebrazenbeard/obsession` draft PR #7, head `cc476d51f7d4f70352fd6122c324ae878e0e87f5`. Work isolated to `obsession_wave7_resident_adapter/`; no GitHub, Lappy, real recipient, or external service mutations.

## Implemented

- `resident_initiative/gate.py`: candidate local SQLite grant binds the exact **full local handoff payload SHA-256**, proposal digest remains embedded inside that payload, protected host operator independently signs `host_grant_request`. Final export uses only host-owned `publish_local`, never client `os.link`, `os.rename`, or a writable outbox; requires exactly pinned custodian output root; reconciles local receipt only after verified host publication response. Retries are idempotent if the protected artifact is identical.
- `resident_initiative/stop_pipe_client.py`: Python custodian v1 adapter using Windows AF_PIPE (AF_UNIX only with explicit test flag), authenticated `multiprocessing.connection.Client` and bounded byte JSON (`send_bytes/recv_bytes`), never pickle. Strict fields, operator-grant HMAC presence, byte payload <=4096, digest, generation, expiry, response receipt and output path validation. Resident lacks protected operator signing key; `.revoke()` deliberately reports operator route required. Legacy `.hold_active()` deliberately fails closed—Python service has no BEGIN/END and lease-based client output cannot establish STOP ordering.
- `tests/stop_fixture.py` and `tests/test_runtime.py`: disposable signed-grant/service-owned-publish semantics.
- `tests/test_stop_admission.py`: adversarial regression including missing publisher, SQLite rollback after synthetic host STOP, outage and forged/wrong signed grant, simultaneous STOP vs host-owned final publication, and expected failure on loss of volatile fixture history.
- `tests/test_custodian_wire_interop.py`: exact cross-component REGISTER → GRANT → signed PUBLISH → idempotent PUBLISH → REVOKE → PUBLISH denial → journal restart-retained STOP through actual sibling `obsession_wave7_custodian_service/stop_custodian.py` handler and byte-JSON fake connection. **This is not a real AF_PIPE service test.**

## Executed source tests

```sh
OBSESSION_DEPS_ROOT=/workspace/scratch/82639ebd4c83/obsession_wave6_stop_tests/obsession-deps \
PYTHONPATH=/workspace/scratch/82639ebd4c83/obsession_wave7_resident_adapter \
python3 -B -m unittest discover \
  -s /workspace/scratch/82639ebd4c83/obsession_wave7_resident_adapter/tests \
  -p 'test_*.py' -q
```

**26 tests PASS** (2.404 seconds at first full passing run). The 26th uses actual Python service request handler, not a mock authorization policy. Dependencies were pinned in the earlier wave's disposable fixture directory. This checks source-level interoperability and hostile cases only; it does not exercise actual Windows identity, ACL, AF_PIPE DACL, service ownership, or protected host custody.

## Release blockers (not closed)

1. **Native protocol choice:** a different native C# custodian candidate uses another STOP/GRANT/PUBLISH protocol; this adapter speaks only the Python service's REGISTER/GRANT/REVOKE/PUBLISH v1. An installer must choose one explicit authority and test the real deployed pair. Never silently use either interchangeably.
2. **Protected owner operation:** resident `.cancel()` always tombstones local SQLite but cannot obtain an independent protected STOP acknowledgement itself: `.revoke()` denies because operator-only key is unavailable. Protected operator STOP route/UI and ceremony remain unimplemented/unqualified in this adapter.
3. **Windows boundary:** current `D:\VERA` host parent inherited broad `Authenticated Users Modify` at preflight. A protected child under replaceable ancestry cannot be assumed safe. Service executable, Python runtime, journal, keys, outbox, pipe DACL, process identity, restart and crash semantics need direct hostile Windows checks before claiming effective protected custody. Windows host installation is **HOLD**, not green.
4. Authenticated transport bytes and signed grants do not by themselves bind service calls to a unique Windows user/scope. Service must enforce correct identity and output ACL; a resident that can directly write protected outputs would bypass STOP.
5. The service journal detects in-place tamper via hash chain but a wholesale protected-journal snapshot rollback needs a distinct immutable anchor; outside this source-only test's qualification.
6. No real recipient send or device integration was built or authorized. Local synthetic handoff only; `contact_authorized=false` and `delivery_verified=false`.

> Hostile review: client-side OS link and a held remote lease cannot guarantee STOP vs publication linearization after IPC disconnect. The fix moves the final filesystem effect to the protected service under the same lock as STOP. Until the actual service is protected against direct write and replacement, this is **source-level semantics**, not a protected-host proof.

**Disposition:** `PYTHON_V1_ADAPTER_SOURCE_TESTS_GREEN / NATIVE_PROTOCOL_HOLD / HOST_CUSTODY_HOLD / CONTACT_HOLD`. No merge/install/deploy effect claimed.
