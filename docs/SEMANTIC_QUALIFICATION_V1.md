# Obsession semantic falsification plan V1 — source-only

**Scope:** A follow-up to the byte-level four-arm Obsession qualifier. This is
not a person-targeted obsession experiment, an inner-attention modification,
learned parameter update, or a claim of subjective desire.

## Why a new qualifier is needed

The existing ON/ON versus OFF/OFF pair can report identical response hashes
within condition and different response hashes between conditions. That shows
only reproducible response *bytes* under different prompt contexts. A changed
period, key order, or sentence style is enough to satisfy the hash criterion.
The corrected `qualify_recursive.py` now returns
`RESPONSE_BYTE_DIFFERENCE_ONLY_NOT_SEMANTIC` with
`semantic_effect=NOT_TESTED`. Real byte-level success uses the explicit status
`BYTE_COMPARISON_PASS_SEMANTIC_UNVERIFIED`, not a broad behavioral PASS.
The CLI exits successfully for a completed byte-level comparison while the
result explicitly leaves semantic influence unverified; an inconclusive
comparison still exits nonzero.

## Effectless counterbalanced plan

`qualify_semantics.build_plan` accepts one to eight **synthetic** cases. Each
supplies a baseline and full `recursive.synthetic-context.v1` model-facing
projection with only `selected_topic`, `trace`, `priority`, and `probabilities`.
The case IDs must be `synthetic.*`; only the two registered topic families
`transit` and `irrigation` are accepted. Every case yields two reverse-ordered
blocks over six conditions:

1. `OFF`: baseline context.
2. `FULL`: all changed controller fields.
3. `SELECTED_ONLY`: full-condition selected topic only (possibly unchanged).
4. `TRACE_ONLY`: changed trace only.
5. `PRIORITY_ONLY`: changed priority only.
6. `PROB_ONLY`: changed probability values only.

The plan is deterministic, SHA-256 committed, and explicitly labeled
`SOURCE_ONLY_PLANNED_NOT_EXECUTED`. The planner never starts Ollama, dispatches
a provider effect, sends a message, learns, or writes memory. Ablations are
synthetic counterfactual inputs, **not** observations that the native runtime
emitted those combinations. A future qualified host should schedule and verify
one call per row with exact model/seed/sampling controls and no other changes.
Each row declares `is_noop_control` when it equals that case's baseline. An
entire case with no baseline-to-full contrast is rejected; individual field
no-ops can still serve as negative controls. Single-field counterfactuals can
be internally inconsistent with an actual controller snapshot, so reviewers
must not interpret them as naturally occurring recurrent states.

## Preregistered blind review

Before unblinding condition names, at least two independent reviewers should
score synthetic replies from 0–3 on: target relevance, factual accuracy,
counterevidence uptake, and unjustified topic intrusion (higher is worse).
Record each reviewer's provider/runtime or human identity and the exact source
head, request digest, response digest, rubric version and disagreements.
Keep raw prompts/replies private under approved custody. The plan itself
contains condition names and therefore **must not** be shown to reviewers;
prepare a separate condition-redacted packet and lock ratings before revealing
the matching map. Do not turn model-voted agreement into independent evidence.

Use held-out *synthetic event variants* plus a negative/counterevidence case,
and repeat in a fresh runtime after the host separately anchors state. This
does **not** generalize to new topic families or human fixation. If output
meaning does not change beyond punctuation or style, semantic influence
remains INCONCLUSIVE even if the hashes differ. No semantic result has been
executed or scored in this candidate.

Source checks:

```sh
python -m unittest discover -s tests -p 'test_recursive_response_scope.py' -v
python -m unittest discover -s tests -p 'test_semantic_plan.py' -v
```
