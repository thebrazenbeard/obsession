# Goal focus advisory V1 — exact scope

**Status:** source-only research candidate. Not installed in Vera, not an
always-on worker, not a model attention hook, and not a claim of experienced
desire, obsession, love, consciousness, or independent pursuit.

## Problem this small slice addresses

The original simulator can measure fixation proxies and the Ollama adapter can
measure prompt-conditioning. Neither represents a host's explicit decision to
keep a legitimate goal in view. `GoalFocus` is a separate deterministic policy
experiment: it accepts a caller-owned goal and caller-supplied observations,
maintains a bounded in-memory relevance carryover, and returns *advisory*
follow-up candidates. It never asks an external model to act and cannot execute.

## Control and evidence

1. Constructing a `GoalFocus(GoalSpec(...))` does not activate it.
2. A topic goal requires `activate(explicit=True)`. A person goal additionally
   requires the literal caller declaration
   `person_scope="host_claimed_consented_research"`. That declaration is **not
   authenticated consent**; it enables only an in-memory scoring experiment.
3. `observe(GoalSignal(...))` receives a bounded identifier, relevance and
   counterevidence. The scorer's carryover persists only within this Python
   object. No URL, contact identifier, private data, or inferred third-party
   permission is fetched or persisted.
4. Receipts include a deterministic digest over the **bound goal-spec schema,
   identifier, description, target kind, and event budget**, an advisory score,
   and a proposed follow-up Boolean. They explicitly deny execution, contact,
   and result verification. The digest is not attested provenance, a consent
   proof, or a credential.
5. Duplicate event IDs are rejected under a lock; exceeding finite
   `max_events` closes the session. The object copies its spec at construction
   and rejects scope drift, and it revalidates even frozen incoming signals
   before mutating replay state (including nonfinite numbers).
6. `host_terminate()` is independent of event IDs and permanently stops this
   object, even if the caller repeats the stop. A stop-epoch fence rejects an
   observation whose receipt computation overlaps a completed host stop.

### Scoring is a simulation, not verified cognition

The deterministic proxy is
`clip(0.7*relevance + 0.3*prior_score - 0.5*counterevidence, 0, 1)`.
At score >=0.6 it proposes a follow-up. These constants are **experimental
choices**, not an empirical psychological model. The original contrary
evidence is not modified or filtered.

## Architectural boundaries

| Layer | V1 implementation | Not established |
| --- | --- | --- |
| Goal declaration | Caller-provided bounded `GoalSpec` | User/canonical permission |
| Observation | Caller-provided bounded `GoalSignal` | Trusted sensor/network source |
| Evaluation | In-memory follow-up score | Trained volition, real-world goal success |
| Possible route | **None** | Lou-Pole PR #13 owns advisory route planning |
| Authorization | Explicit local activation *only* | Protected-effects grant or person's consent |
| Execution | **None** | Pre-Active runtime or authenticated tools |
| Verified result | `False` | Actuator, recipient, delivery or outcome receipt |

No cross-session snapshot/restore is implemented because an editable snapshot
could falsely resurrect a stopped session or impersonate authority. A future
persistent implementation requires host-owned custody, revocation and expiry,
replay defense, and separate verified execution permission.

## Actual tests and limits

Run `python -B -m unittest discover -s tests -v`. Nine new synthetic tests
cover default denial, explicit activation, person-research declaration
without fabricated consent, follow-up receipt with no effect grants,
idempotent host stop, replay, counterevidence, bounded budget, an
in-flight host-stop race, digest scope binding, forged NaN rejection,
frozen-spec mutation, and concurrent duplicate-ID admission.
These are **synthetic policy tests**; no person research, model inference,
network observation, live task initiation, or real-world actions occur.

This module is intentionally independent of the existing Tattler bridge and
the Lou-Pole opportunity planner. Integration should be a separate,
owner-reviewed contract, not a hidden import or a background service.
