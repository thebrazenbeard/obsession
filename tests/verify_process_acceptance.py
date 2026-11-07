"""Independent process acceptance with synthetic providers, never phone delivery.

The production CLI initializes, reads, cancels and exports trial state. Separate
Python workers exercise the public Runtime API with explicitly unverified
provider fixtures; no HTTP or model inference is involved in this verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def worker(args):
    from resident_initiative.runtime import Runtime, canonical
    from pre_active.engine import ModelResponse, RetryableModelError

    class Fixture:
        evidence_class = "SYNTHETIC_PROCESS_PROVIDER_UNVERIFIED"
        calls = 0

        def respond(self, *, messages, tools):
            if tools:
                raise AssertionError("fixture received executable tools")
            self.calls += 1
            if args.entered:
                Path(args.entered).write_text(encoded({"pid": os.getpid()}))
                deadline = time.monotonic() + 12
                while not Path(args.release).exists():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("synthetic process barrier expired")
                    time.sleep(.02)
            if args.mode == "failure":
                raise RetryableModelError("synthetic transport unavailable", category="synthetic")
            return ModelResponse(final_text=canonical({
                "message": "Synthetic diagnostic ready.",
                "reason": "Configured finite process test.",
            }))

    provider = Fixture()
    runtime = Runtime(args.db, provider)
    try:
        if args.mode == "submit":
            result = runtime.submit_signal("synthetic.process-event", args.relevance)
            print(encoded({"pid": os.getpid(), "event": result}), flush=True)
            return 0
        cycles = 0
        deadline = time.monotonic() + args.seconds
        last = None
        while time.monotonic() < deadline:
            last = runtime.cycle()
            cycles += 1
            if args.crash_after and cycles >= args.crash_after:
                os._exit(17)
            if last["state"] in {"CANCELLED", "EXPIRED", "CLOCK_ROLLBACK", "SCOPE_CHANGED"}:
                break
            status = runtime.status()
            if status["proposals"] and status["pending_events"] == 0:
                break
            time.sleep(.03)
        status = runtime.status()
        print(encoded({"pid": os.getpid(), "calls": provider.calls, "cycles": cycles,
                       "state": status["state"], "last": last}), flush=True)
        return 0
    finally:
        runtime.close()


def source_hashes():
    paths = [*sorted((ROOT / "resident_initiative").glob("*.py")),
             ROOT / "dependency-lock.json", Path(__file__).resolve()]
    return {str(p.relative_to(ROOT)).replace("\\", "/"):
            hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def verify(args):
    from resident_initiative.deps import PROVENANCE

    checks = []
    commands = []
    source_before = source_hashes()
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"

    def call(argv, *, expected=0, timeout=18):
        command = [sys.executable, "-B", *map(str, argv)]
        result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True,
                                text=True, timeout=timeout)
        commands.append({"argv": command, "exit_code": result.returncode})
        if result.returncode != expected:
            raise AssertionError(encoded({"expected_exit": expected, "exit": result.returncode,
                                          "stdout": result.stdout[-3000:], "stderr": result.stderr[-3000:]}))
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        return json.loads(lines[-1]) if lines and expected == 0 else result

    def cli(*argv, **kwargs):
        return call(["-m", "resident_initiative", *argv], **kwargs)

    def fixture(db, *argv, **kwargs):
        return call([__file__, "--child", "--db", db, *argv], **kwargs)

    def check(name, condition, **detail):
        if not condition:
            raise AssertionError(name + ": " + encoded(detail))
        checks.append({"check": name, "result": "PASS", **detail})

    def init(path, *, ttl=90, events=1):
        return cli("init", "--db", path, "--ttl-seconds", ttl,
                   "--interval-seconds", 3600, "--max-events", events)

    with tempfile.TemporaryDirectory(prefix="initiative-process-verify-") as temporary:
        base = Path(temporary)
        timer_db = base / "timer.db"
        initialized = init(timer_db)
        first = fixture(timer_db)
        status = cli("status", "--db", timer_db)
        check("independent_timer_process_proposes", first["pid"] != os.getpid()
              and first["calls"] == 1 and len(status["proposals"]) == 1
              and status["proposals"][0]["event_id"].startswith("timer."), child_pid=first["pid"])
        proposal = status["proposals"][0]
        proposal_id = proposal["proposal_id"]
        check("proposal_has_no_contact_or_effect_authority",
              proposal["contact_authorized"] is False
              and proposal["execution_authorized"] is False
              and proposal["delivery_verified"] is False
              and proposal["target_class"] == "SYNTHETIC_LOCAL_ONLY"
              and proposal["provider_evidence"] == "SYNTHETIC_PROCESS_PROVIDER_UNVERIFIED")
        restarted = fixture(timer_db, "--seconds", .2)
        status_again = cli("status", "--db", timer_db)
        check("fresh_process_reuses_durable_proposal",
              restarted["calls"] == 0 and status_again["proposals"] == [proposal]
              and status_again["generation"] == initialized["generation"])

        outbox = base / "local-handoff"
        forged = base / "forged.json"
        forged.write_text(encoded({"scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "grant_id": "unissued"}), encoding="utf-8")
        rejected = cli("export", "--db", timer_db, "--proposal", proposal_id,
                       "--grant-file", forged, "--directory", outbox, expected=1)
        denied_status = cli("status", "--db", timer_db)
        check("unissued_grant_rejected_before_artifact",
              not outbox.exists() and any(x["disposition"] == "REJECTED_LOCAL_HANDOFF"
                                         for x in denied_status["receipts"]))
        grant_file = base / "issued.json"
        cli("grant-local", "--db", timer_db, "--proposal", proposal_id,
            "--grant-file", grant_file, "--directory", outbox, "--ttl-seconds", 30)
        exported = cli("export", "--db", timer_db, "--proposal", proposal_id,
                       "--grant-file", grant_file, "--directory", outbox)
        artifact = Path(exported["path"])
        body = json.loads(artifact.read_text(encoding="utf-8"))
        check("explicit_host_grant_exports_local_synthetic_only",
              body["scope"] == "LOCAL_SYNTHETIC_HANDOFF_ONLY"
              and body["contact_authorized"] is False and body["delivery_verified"] is False
              and body["proposal"] == proposal
              and hashlib.sha256(artifact.read_bytes()).hexdigest() == exported["sha256"])
        repeated = cli("export", "--db", timer_db, "--proposal", proposal_id,
                       "--grant-file", grant_file, "--directory", outbox)
        check("handoff_replay_reuses_exact_artifact",
              repeated == exported and len(list(outbox.glob("*.json"))) == 1)
        wrong = base / "wrong-directory"
        cli("export", "--db", timer_db, "--proposal", proposal_id,
            "--grant-file", grant_file, "--directory", wrong, expected=1)
        check("grant_cannot_widen_export_directory", not wrong.exists())

        cancelled = cli("cancel", "--db", timer_db)
        after_cancel = fixture(timer_db)
        check("cancellation_tombstone_survives_fresh_process",
              cancelled["state"] == "CANCELLED" and after_cancel["state"] == "CANCELLED"
              and after_cancel["calls"] == 0)
        cli("export", "--db", timer_db, "--proposal", proposal_id,
            "--grant-file", grant_file, "--directory", outbox, expected=1)
        check("cancellation_blocks_previously_granted_export", len(list(outbox.glob("*.json"))) == 1)

        event_db = base / "event.db"
        init(event_db)
        a = fixture(event_db, "--mode", "submit")
        b = fixture(event_db, "--mode", "submit")
        conflict = fixture(event_db, "--mode", "submit", "--relevance", .8, expected=1)
        fixture(event_db)
        c = fixture(event_db, "--mode", "submit")
        status = cli("status", "--db", event_db)
        check("duplicate_event_does_not_amplify_across_processes",
              a["event"] == b["event"] == c["event"] and len(status["signals"]) == 1
              and len(status["proposals"]) == 1
              and status["proposals"][0]["event_id"] == "synthetic.process-event")
        check("changed_event_identity_rejected", "ValueError" in conflict.stderr)

        crash_db = base / "crash.db"
        init(crash_db)
        fixture(crash_db, "--crash-after", 1, expected=17)
        recovered = fixture(crash_db)
        status = cli("status", "--db", crash_db)
        check("abrupt_pre_inference_process_exit_recovers_once",
              recovered["calls"] == 1 and len(status["signals"]) == len(status["proposals"]) == 1)

        held_db = base / "held.db"
        init(held_db)
        entered, release = base / "entered.json", base / "release"
        command = [sys.executable, "-B", __file__, "--child", "--db", str(held_db),
                   "--entered", str(entered), "--release", str(release), "--seconds", "10"]
        process = subprocess.Popen(command, cwd=ROOT, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 7
            while not entered.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError("held worker exited before entering provider")
                time.sleep(.03)
            check("separate_process_provider_enters_barrier", entered.exists())
            cancelled = cli("cancel", "--db", held_db)
            check("cancel_commits_while_other_process_provider_is_inflight",
                  cancelled["state"] == "CANCELLED" and process.poll() is None)
            release.write_text("release", encoding="ascii")
            stdout, stderr = process.communicate(timeout=12)
            commands.append({"argv": command, "exit_code": process.returncode})
            if process.returncode != 0:
                raise AssertionError(stderr[-3000:] + stdout[-3000:])
            status = cli("status", "--db", held_db)
            check("late_inflight_result_is_fenced_after_cancel",
                  status["state"] == "CANCELLED" and status["proposals"] == []
                  and any(x["disposition"] == "REJECTED_STALE_RESULT" for x in status["receipts"]))
        finally:
            release.touch()
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

        failure_db = base / "failure.db"
        init(failure_db)
        failing = fixture(failure_db, "--mode", "failure", "--seconds", .4)
        status = cli("status", "--db", failure_db)
        check("synthetic_provider_failure_has_no_authorization_or_proposal",
              failing["calls"] == 1 and status["proposals"] == []
              and status["contact_authorized"] is False
              and any(x["disposition"] == "DEFERRED_MODEL_FAILURE" for x in status["receipts"]))
        immediate = fixture(failure_db, "--seconds", .1)
        check("restart_preserves_provider_backoff", immediate["calls"] == 0)
        recovered = fixture(failure_db, "--seconds", 4)
        status = cli("status", "--db", failure_db)
        check("synthetic_provider_recovery_reuses_pending_event",
              recovered["calls"] == 1 and len(status["signals"]) == len(status["proposals"]) == 1)

    source_after = source_hashes()
    check("source_unchanged_during_acceptance", source_before == source_after)
    receipt = {"schema": "initiative.independent-process-acceptance.v1", "result": "PASS",
               "checks_passed": len(checks), "checks": checks, "commands": commands,
               "source_sha256": source_after, "dependencies": PROVENANCE,
               "evidence_class": "EXECUTED_PROCESS_TEST_WITH_SYNTHETIC_UNVERIFIED_PROVIDER",
               "model_inference": False, "phone_contact": False, "device_delivery_verified": False}
    if args.output:
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded(receipt) + "\n", encoding="utf-8")
    print(encoded(receipt))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--db")
    parser.add_argument("--mode", choices=("success", "failure", "submit"), default="success")
    parser.add_argument("--relevance", type=float, default=.9)
    parser.add_argument("--seconds", type=float, default=2)
    parser.add_argument("--entered")
    parser.add_argument("--release")
    parser.add_argument("--crash-after", type=int)
    parser.add_argument("--output")
    args = parser.parse_args()
    return worker(args) if args.child else verify(args)


if __name__ == "__main__":
    raise SystemExit(main())
