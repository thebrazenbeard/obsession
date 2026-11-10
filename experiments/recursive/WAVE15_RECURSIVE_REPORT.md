# Wave 15: recursive source integration under protected STOP

Status: **isolated candidate / not committed to GitHub**. No host, service,
recipient, credential, permission or protected-output effects occurred.

## Authoritative material

- Obsession Draft PR #9 protected STOP head:
  `c42c8afc39a1a98bc4b4f3b4e5889475764d8ccd` (base PR #8
  `a195d6ea204c728e759c487210926408233ec20f`).
- Separate recursive Draft PRs #3–6, tip:
  `a50027b4d1f7aaecf6bf794579fd64fd6db0b677`. Open, unmerged.
- The isolated checkout was materialized from exact PR #9 source and its
  `dependency-lock.json` pinned Pre-Active commit
  `e306c251a4da44125ee58c311a35120084da8e4b` and GoalFocus blob
  `3518c5ea49d40d1f0e90adda98bdeac30381525a`.
- PR6 recursive/context modules, real recursive tests, fixture and diagnostic
  qualifier were brought over with line endings normalized. They are
  semantically unchanged from PR6; the only edited production module is
  `resident_initiative/runtime.py`.

## Narrow implementation

Five small runtime hunks:

1. Opt-in exact `RecursiveDrive` type after owner/config verification; default
   `None` remains non-recursive and `stop_authority` remains independent.
2. Add model-facing recursive context only inside `GuardedModel.respond`
   when enabled.
3. Admit completed low-salience deferrals into recurrence trace in SQLite
   transaction.
4. Admit completed synthetic proposals in the same transaction as proposal
   creation; retry replay cannot reapply an event.
5. Preserve all PR9 protected gate, STOP cancellation and local publication
   controls without touching `gate.py`.

Additional mixed test `tests/test_recursive_stop_integration.py` proves that
a committed recursive event does not create a host custodian, and even an
ordinary local SQLite grant cannot publish without an independent operator
signature. It also proves that restoring a pre-STOP SQLite snapshot containing
recursive history cannot erase a still-existing external STOP witness. These
tests use a disposable synthetic custodian, not real Windows cross-token security.

## RED→GREEN and test evidence

- Exact PR9 source + new PR6 recursive tests before runtime patch:
  **7 errors**. Six were `Runtime.__init__() got an unexpected keyword
  argument 'recursive_drive'`; one was a missing PR6 test dependency
  `qualify_recursive`. This established the missing feature seam.
- Exact PR9 unmodified baseline `tests/test_runtime.py`:
  **18/18 PASS** with pinned dependencies.
- After adding PR6 recursive/context/qualifier and the five runtime hunks,
  `tests/test_recursive*.py`: **9/9 PASS**.
- Combined `tests/test_runtime.py`, `tests/test_stop_admission.py`,
  `tests/test_recursive*.py` and mixed protected-STOP test:
  **37/37 PASS**, 0.678 seconds, exit code 0.

Run from the workspace scratch root:

```bash
OBSESSION_DEPS_ROOT=$PWD/obsession_wave15_recursive_reconcile_checkout/deps \
PYTHONPATH=obsession_wave15_recursive_reconcile_checkout \
python -m unittest discover \
  -s obsession_wave15_recursive_reconcile_checkout/tests -p 'test_*.py' -q
```

SHA-256 (normalized LF scratch):

- Runtime candidate: `482e6ed06b272006c41dd8326fd2092fb53378f77914bbe3909ab20122e44165`
- Recursion module: `d99bacadeaa681fb48258ee9ac20a291cc8be90f04d9ca7e43518d5d8bece27b`
- Context formatter: `e6765e9f9bb8670d6fb28f4a9563b18f464b4b104b56c79d9fe6585bdee6febe`
- Mixed STOP regression: `3d5511e0fdace89ac4a062e4baba85c4db77a66c25c0f2f3ca55c499fc9d1e1d`
- PR6 qualifier: `e2fd7bb02aa6f1b024b24536ec70b09ec2bd4221c1d8b8e8692eab7e3c5545a6`

## Hostile holds

> The PR6 `gate.py` uses direct local `os.link/os.rename` publication after
> local SQLite approval. Never cherry-pick it across PR9's independently
> protected STOP gate. The PR9 `gate.py` is untouched here.

> The 37 tests qualify local software behavior, not real protected Windows
> custody, external anti-rollback witness, recipient contact, nor service
> deployment. Source PR6's `backend.py`, README, and broad runtime tests still
> require separate semantic reconciliation. No merge/push/release authority
> is inferred from PASS.

## Parent integration recipe

From this isolated checkout, consider only:

- `resident_initiative/runtime.py` (5 hunks, diff against live PR9).
- PR6 `resident_initiative/recursive.py`, `context_format.py`,
  `qualify_recursive.py`, `tests/test_recursive.py`,
  `tests/test_recursive_response_scope.py`,
  `tests/fixtures/recursive_semantics_v1.json`.
- New `tests/test_recursive_stop_integration.py`.

Do not copy `deps/` into the repo; these are pinned test reproductions.
Preserve exact GitHub file blobs and their line endings when publishing.
