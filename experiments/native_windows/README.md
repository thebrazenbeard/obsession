# Native Windows STOP custodian — source-only qualification candidate

Target: **Windows 11 Home, .NET Framework 4.x, LocalSystem**. Do not deploy this package yet.

This source is a proposed alternative to a user-writable Python runtime. Lappy has two Microsoft-signed .NET Framework 4.0 C# compilers:

- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`

Both signatures were returned `Valid`, signer `Microsoft Windows`, in a read-only WorkBridge probe. The final revised source **compiled without warnings** on Lappy with `/warnaserror+` in isolated `D:\VERA\experiments\obsession-native-stop-custodian-stage-20261107-4bd8`. Production and test-only executables were built separately. Neither version has been installed, registered with SCM, or run as a service.

## Proposed host boundary

1. Build a native .NET Framework Windows Service from `ObsessionStopCustodian.cs` using the signed system compiler (only after host write approval).
2. Protected code, journal and protected output under `C:\Program Files\VERA\ObsessionStopCustodian`, which needs Patrick's separate path authorization. `D:\VERA` remains the integration workspace; **it cannot be the protected journal root** because both its parent and `D:` grant broad Modify.
3. Service process identity `LocalSystem`, exclusive service name and named pipes.
4. Operator pipe only SYSTEM+Administrators may issue `GRANT` or `STOP`; publish pipe restricted to an exact resident SID selected by the operator.
5. Both operations serialize through one lock. `STOP` writes/flushes durable tombstone before successful acknowledgement. `PUBLISH` checks an independently stored operator grant and STOP journal, then **service** writes the artifact under protected output with atomic no-replace semantics.
6. Resident must not be able to write protected output or to access operator pipe; owner grants must never be minted from rollback-prone resident SQLite alone.
7. No phone/network/recipient contact is implemented.

## Staging build performed (never deploy the self-test variant)

```powershell
& 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' /nologo /warnaserror+ /target:exe /out:ObsessionStopCustodian.exe /reference:System.ServiceProcess.dll /reference:System.Core.dll /reference:System.Web.Extensions.dll ObsessionStopCustodian.cs
```

Host evidence (final exact source):

- Source SHA-256: `6B170584105AFF1B8796EFECFFD44F620279B5029C1EADAC72E5792F991F714C`.
- Production candidate EXE SHA-256: `0EF2C93C2F9BB37AF822EF61439CAA92E43CAF7BF3F010772EB0457031E3D6F9`.
- `STAGING_SELFTEST` EXE SHA-256: `912B0D570B61550C8A2673794AA612D5D7C3C373C8C1F9B08657C6CAE39C725E`.
- Compiler messages: `[]` (two builds with zero output, `/warnaserror+`).
- Earlier same semantic code with only a leading comment difference had staging
  semantic test `GRANTED -> PUBLISHED -> STOPPED -> HOLD(after STOP) -> HOLD(after reload)`, exit code `0`.
  This was an in-process harness with staging ACL/SCM checks **excluded** by
  conditional compilation; it does **not** verify named-pipe identity, ACLs,
  SCM startup, or a protected installation.

## Qualifications not met

- No Windows SCM registration, live service process, authenticated named-pipe
  fixture, effective ACL/DELETE_CHILD test, or machine restart witness.
- This source assumes **Administrators and LocalSystem are trusted**. In the current configuration, the AI-accessible WorkBridge endpoint is itself elevated administrator; **that endpoint can rewrite the protected custodian**, defeating independence from the same AI. Restrict its capabilities before asserting a protected STOP boundary.
- Pipe DACL, Windows ACL and race tests must be run under actual distinct Windows tokens.
- A local admin can deliberately replace the journal. Hashing alone does not prevent rollback against a privileged administrator.
- Service installer and resident adapter are separate workstreams; do not activate publication without their tested binding.

The revised source also requires a protected `binary.sha256` sidecar (lowercase hexadecimal SHA-256), exact protected executable path and SCM registry `ImagePath`/`LocalSystem` account identity, rejects writable ACLs on root ancestors, and allows only the current six-field synthetic local JSON handoff. The nested proposal dictionary is not semantically whitelisted, so production activation remains **HOLD** until schema constraints are independently validated. These checks are not a solution to privileged-administrator compromise.

Disposition: `SOURCE_STAGE_COMPILATION_ONLY / HOST_AUTHORITY_HOLD / CONTACT_DISABLED`.
