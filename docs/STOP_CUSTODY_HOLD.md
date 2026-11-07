# Resident STOP boundary: source-only candidate, not installed

An explicit local synthetic grant previously survived a restored pre-STOP
SQLite snapshot. `LocalHandoffGate` now stages a candidate resident grant only
after verifying a publisher binding. The protected operator must separately
sign a narrowly scoped grant over SHA-256 of the exact final local-only payload.
The resident cannot mint that signature.

The final handoff is emitted **only through the custodian's PUBLISH opcode**,
inside the service's exclusive STOP/publication lock. Resident-side
`os.link`/`os.rename` and legacy BEGIN/END held leases are prohibited; the
adapter's `hold_active` intentionally fails closed. The default has no
publisher configured, so grant/export fails closed. Synthetic providers exist
for tests only, not production.

The Python service candidate defines REGISTER/GRANT/REVOKE/PUBLISH over
authenticated byte-JSON IPC. An alternate native Windows C# candidate has an
incompatible wire grammar. Choose and verify the actual intended service before
host deployment. Owner REVOKE must be separately routed to a protected operator;
resident `.cancel()` conservatively persists a local tombstone and reports the
host STOP outcome as unverified when operator authority is absent.

Full effective Windows ACL/identity, pipe DACL, cross-process STOP timing,
durable host restart and replacement resistance are **not** demonstrated by
source-only test fixtures. The initial `D:\VERA` parent inherited broad write
permissions and is not an assumed protected root.

No phone transport exists here, and this candidate authorizes no contact.
Release remains `NATIVE_PROTOCOL_HOLD / HOST_CUSTODY_HOLD / CONTACT_HOLD`.
See `REPORT.md` for the exact PR head, test command, 26/26 synthetic source
tests including real Python service handler byte-JSON interop, and limitations.
