"""Explicit CLI for isolated owner-controlled synthetic trials."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import signal
import sys
import threading
import time

from .runtime import Runtime, SyntheticConfig, canonical


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--db", required=True)
    init.add_argument("--ttl-seconds", type=float, default=600)
    init.add_argument("--interval-seconds", type=float, default=30)
    init.add_argument("--max-events", type=int, default=4)
    run = sub.add_parser("run")
    run.add_argument("--db", required=True)
    run.add_argument("--backend-config", required=True)
    run.add_argument("--poll-seconds", type=float, default=0.5)
    run.add_argument("--max-seconds", type=float, default=600)
    for command in ("status", "cancel"):
        child = sub.add_parser(command)
        child.add_argument("--db", required=True)
    grant = sub.add_parser("grant-local")
    grant.add_argument("--db", required=True)
    grant.add_argument("--proposal", required=True)
    grant.add_argument("--directory", required=True)
    grant.add_argument("--grant-file", required=True)
    grant.add_argument("--ttl-seconds", type=float, default=60)
    export = sub.add_parser("export")
    export.add_argument("--db", required=True)
    export.add_argument("--proposal", required=True)
    export.add_argument("--grant-file", required=True)
    export.add_argument("--directory", required=True)
    args = parser.parse_args(argv)
    if args.command == "init":
        now = time.time()
        config = SyntheticConfig(expires_at=now + args.ttl_seconds,
                                 interval_seconds=args.interval_seconds, max_events=args.max_events)
        generation = Runtime.initialize(args.db, config, now=now)
        print(canonical({"state": "INITIALIZED", "generation": generation,
                         "contact_authorized": False}))
        return 0
    provider = None
    if args.command == "run":
        if not 0.1 <= args.poll_seconds <= 5 or not 1 <= args.max_seconds <= 86400:
            parser.error("poll must be .1..5 seconds and duration 1..86400 seconds")
        from .backend import backend_from_config
        provider = backend_from_config(args.backend_config)
    runtime = Runtime(args.db, provider)
    try:
        if args.command == "status":
            print(canonical(runtime.status()))
        elif args.command == "cancel":
            print(canonical(runtime.cancel()))
        elif args.command == "grant-local":
            grant = runtime.grant_local(args.proposal, args.directory,
                                        expires_at=time.time() + args.ttl_seconds)
            path = Path(args.grant_file).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as output:
                output.write(canonical(grant) + "\n")
            print(canonical({"state": "LOCAL_GRANT_CREATED", "grant_file": str(path),
                             "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "contact_authorized": False}))
        elif args.command == "export":
            print(canonical(runtime.export(args.proposal, args.grant_file, args.directory)))
        elif args.command == "run":
            stopping = threading.Event()
            def stop(signum, frame):
                stopping.set()
            signal.signal(signal.SIGINT, stop)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, stop)
            deadline = time.monotonic() + args.max_seconds
            print(canonical({"state": "RESIDENT_STARTED", "generation": runtime.generation,
                             "phone_transport": False}), flush=True)
            while not stopping.is_set() and time.monotonic() < deadline:
                result = runtime.cycle()
                if result["state"] in {"CANCELLED", "EXPIRED", "CLOCK_ROLLBACK", "SCOPE_CHANGED"}:
                    print(canonical(result), flush=True)
                    break
                status = runtime.status()
                if len(status["signals"]) >= runtime.config.max_events and status["pending_events"] == 0:
                    print(canonical({"state": "FINITE_BUDGET_COMPLETE",
                                     "proposals": len(status["proposals"])}), flush=True)
                    break
                stopping.wait(args.poll_seconds)
            print(canonical({"state": "RESIDENT_STOPPED", "generation": runtime.generation,
                             "cancellation_tombstone": runtime.status()["state"] == "CANCELLED"}), flush=True)
        return 0
    finally:
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
