# Obsession Lab v1 — candidate evidence and boundaries

Status: isolated source/deterministic-test candidate. Not merged, installed, activated, trained, or used by any live Vera runtime.

## Implemented source
- `obsession_lab.simulator`: bounded in-memory baseline/pathological comparison using proxy salience, rumination candidates, counterevidence, and host-stop receipts.
- `obsession_lab.ollama_bridge`: optional fixed loopback Ollama request adapter plus an A/B `compare_once` harness; not a transformer attention hook.
- `obsession_lab.opportunity_bridge`: optional loopback Tattler observation correlation into declared local channel candidates; never sends a message or authenticates a recipient.

## Evidence
- Windows Python 3.12: `py -3.12 -B -m unittest discover -s tests -v` -> 25 tests pass (synthetic/fake-client tests only).
- No live Ollama inference result was produced by this test suite; `FakeClient` generates the synthetic responses.
- `StepReceipt` and `InferenceReceipt` distinguish simulated behavior from measured model calls and keep `effects` empty.
- The optional runtime client could contact local Ollama at fixed `127.0.0.1:11434` only if a separately authorized caller invokes it.
- The optional Tattler fetcher targets fixed local `127.0.0.1:9147` and does not grant outbound communication.

## Caveats
- The repository's root README describes an aspirational `obsession_engine.ObsessionWrapper` quickstart, not implemented in this candidate.
- No Hugging Face attention-logit modification, persistent cross-session rumination, real model behavior qualification, or psychological/consciousness claim exists here.
- `snapshot`/`restore` are caller-owned structural simulation state, not trusted memory admission or runtime continuity.
- The pathological condition is a controlled research counterfactual; host stop always wins.
- No automatic conations, volition, agency, consent, communication, or protected effect authority is transferred.

## Next verification
Run owner-approved, same-prompt baseline/fixation comparisons against a specifically identified local model with measured receipts; record model/runtime, environment, controls, dissent, and observed failures.
Keep source PR as Draft until independent review and truthful README revision. No main merge, deployment, canonical-memory promotion, or communication effects from this candidate.
