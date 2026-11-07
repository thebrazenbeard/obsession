# Synthetic resident initiative candidate

This disjoint integration candidate runs a finite synthetic goal on a real
Pre-Active timer and lease-based worker. GoalFocus scores admitted observations;
an authenticated model adapter may draft a proposal. A separate local output gate
defaults to denial. This source has no phone transport, recipient configuration,
gateway token, canonical-memory write, or general model-facing tool.

The runtime is software scheduling and inspectable host-owned work state. It is
not a transformer attention modification, persistent subjective fixation, or
proof of identity continuity with a ChatGPT conversation.

## Exact dependencies

No package installation is needed. Python 3.11+ and the standard library suffice.
The candidate verifies every dependency blob listed in `dependency-lock.json`
against its Git blob hash before importing it:

- `thebrazenbeard/pre-active` at `e306c251a4da44125ee58c311a35120084da8e4b`.
- `thebrazenbeard/obsession` GoalFocus at `6ed7d325bd33ac49098f4220e0fb7b05ed6d2f64`.

Use `python -B fetch_dependencies.py --help` for the pinned dependency fetcher;
it verifies source Git hashes and refuses to overwrite divergent existing files.
Place exact source checkouts/exports in sibling `obsession-deps/pre-active` and
`obsession-deps/obsession`, or set `OBSESSION_DEPS_ROOT` to their parent. Preserve
Git source line endings. The GoalFocus module is loaded directly after hash
verification; no editable simulation snapshot is imported or resumed.

## Trial commands

Keep runtime DBs, backend configuration, tokens, logs and owner checkpoints in
private owner-controlled storage. No credential belongs in a command argument,
public issue, source repository, or printed status. The backend configuration
contract and isolated broker are defined in `resident_initiative/backend.py`.

From the candidate source directory:

```text
python -B -m resident_initiative init --db PRIVATE_DB --ttl-seconds 600 --interval-seconds 30 --max-events 4
python -B -m resident_initiative run --db PRIVATE_DB --backend-config PRIVATE_CONFIG --max-seconds 600
python -B -m resident_initiative status --db PRIVATE_DB
python -B -m resident_initiative cancel --db PRIVATE_DB
```

The CLI starts no Windows service or scheduled task. An independently launched
process runs without a ChatGPT conversation. Ctrl-C/SIGTERM ends the process at
its next bounded checkpoint. `cancel` additionally writes a permanent generation
tombstone and requests durable Pre-Active run cancellation. Blocking inference
is fenced after return; it is not falsely described as immediately aborted.

`status` reports the **persisted trial owner**, not whether a worker process is
running. Its legacy `state=ACTIVE` means the generation has not been tombstoned
or expired by a subsequent runtime checkpoint. A finite `run` may print
`FINITE_BUDGET_COMPLETE` and `RESIDENT_STOPPED` and exit while the persisted
owner still says `ACTIVE` and the schedule's enabled flag remains set. The
additive `state_subject`, `worker_liveness`, and `schedule_flag_subject` fields
make that separation explicit. `observation_budget_remaining=0` reports only
the observation cap, not that a resident worker or service is alive. Process
liveness requires a separate host process/lease check; neither the database nor
this CLI status attests it. Opening `status` does not renew process liveness,
mark an expired owner terminal, or restart a worker.

## Persistence and failure behavior

One SQLite file holds the existing Pre-Active queue, scheduler, leases and run
decisions plus a small host-owned goal journal, receipts, local proposals and
grants. GoalFocus is reconstructed through its public API by replaying bounded
admitted signals. No hidden field or unauthenticated research restore is used.

At most 32 admitted events and three inference attempts per event are permitted.
The default trial uses four events. Pending work suppresses new timer ticks;
missed intervals are coalesced into one due tick instead of a catch-up storm.
Provider failure uses Pre-Active's durable bounded exponential backoff. Process
restart reuses the same event and proposal identities. A permanently cancelled,
expired, or clock-rollback-held generation cannot reactivate itself.

The host checks generation, expiry and cancellation before inference, after
inference, when collecting the committed result, and at the output boundary.
Pre-Active additionally fences leased writes and checks durable run control.
There are zero external or internal scheduling tools; model output must contain
exactly `message` and `reason` strings within fixed caps. Model authority fields,
tool calls and duplicate JSON keys fail closed.

Local same-user code and storage are trusted. File hashes detect changed bytes;
they do not establish independent publisher authentication or defeat an attacker
who controls this process, the owner account, or all state files. Back up the DB
and its SQLite WAL together using a proper SQLite backup before any replacement.

## Local handoff interface

`initiative.proposal.v1` carries a stable proposal/idempotency key, event ID,
goal/config digest, generation, expiry, bounded message/reason, advisory receipt
and exact dependency heads. Host-set `origin=OBSESSION_RESIDENT_SYNTHETIC_V1`,
`category=OWNER_DIRECTED_SYNTHETIC_DIAGNOSTIC`, `propose_only=true`, evidence class
and creation-bound TTL cannot be supplied by model output. `execution_authorized`, `contact_authorized` and
`delivery_verified` remain false. Injected test providers are labelled unverified.

Vera 1 may review this proposal contract without changing its owned gateway or
APK. No delivery endpoint is inferred. A future authenticated consumer must bind
its own owner permission, recipient, expiry and idempotency, and distinguish
gateway acceptance, device receipt/render and reply. A local artifact or HTTP
success cannot substitute for these proofs.

An explicit owner-only local export is available for review:

```text
python -B -m resident_initiative grant-local --db PRIVATE_DB --proposal PROPOSAL_ID --directory PRIVATE_OUT --grant-file PRIVATE_GRANT --ttl-seconds 60
python -B -m resident_initiative export --db PRIVATE_DB --proposal PROPOSAL_ID --directory PRIVATE_OUT --grant-file PRIVATE_GRANT
```

The separate `LocalHandoffGate` freshly verifies the proposal body digest and
synthetic schema invariants and requires a persisted digest/generation/directory
bound grant. A fabricated JSON grant alone cannot authorize anything. Export is
atomic, uses one stable filename and verifies exact existing bytes on repeat.
Divergent artifacts are never overwritten. Even a valid local grant grants zero
person-contact authority. Model output cannot issue grants or call this gate.

## Verification

```text
python -B -m unittest discover -s tests -v
```

The focused runtime suite covers real substrate timer execution, restart/dedupe,
conflicting IDs, score replay, unauthorized model fields/tools, cancellation
during blocked inference, expiry, sticky clock rollback, bounded retry/backoff,
finite budgets and default-denied/idempotent local export. Test-provider behavior
is synthetic. Authenticated HTTP tests and real local-model/process acceptance
are distinct evidence surfaces; record their actual execution separately.

No merge, production install, gateway replacement, phone send, app notification,
device rendering, reply, or canonical memory effect follows from this candidate.
