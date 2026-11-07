"""Explicit one-shot local-model qualification; writes private trial evidence.

This never calls a messaging endpoint. Run on the authorized Windows host with
--private-root set to an owner-controlled directory that does not already exist.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import time

from resident_initiative import backend as b
from resident_initiative.runtime import Runtime, SyntheticConfig, canonical


ROOT = Path(__file__).resolve().parent


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, required=True)
    args = parser.parse_args(argv)
    private = args.private_root.resolve()
    private.mkdir(parents=True, exist_ok=False)
    cfg = {"schema":b.SCHEMA,"port":unused_port(),"model":"qwen2.5-coder:1.5b-instruct-q8_0",
           "token_file":str(private/"broker.key"),"broker_state":str(private/"broker.sqlite3"),
           "timeout_seconds":60,"max_tokens":256,"expires_at":time.time()+900,"max_calls":4}
    (private/"broker.key").write_text(secrets.token_hex(32),encoding="ascii")
    config_path=private/"backend.json"
    config_path.write_text(canonical(cfg),encoding="utf-8")
    evidence={"schema":"initiative.real-local-qualification.v1","started_at":time.time(),
        "phone_sends":0,"delivery_verified":False,"cases":{},
        "source_hashes":{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted((ROOT/"resident_initiative").glob("*.py"))}}
    children=[]
    files=[]
    def start(label,cmd):
        log=(private/(label+".log")).open("w",encoding="utf-8")
        files.append(log)
        child=subprocess.Popen([sys.executable,"-B",*cmd],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
        children.append(child)
        evidence.setdefault("processes",[]).append({"label":label,"pid":child.pid})
        return child
    def state(db):
        runtime=Runtime(db)
        try:
            return runtime.status()
        finally:
            runtime.close()
    def count_admissions():
        with closing(sqlite3.connect(cfg["broker_state"])) as db:
            return db.execute("SELECT count(*) FROM admissions").fetchone()[0]
    try:
        broker=start("broker",["-m","resident_initiative.backend","broker","--config",str(config_path)])
        deadline=time.monotonic()+10
        while True:
            try:
                status,_,_=b._post(cfg["port"],"/v1/evaluate",b"{}",{"Content-Type":"application/json"},2)
                if status==401:
                    break
            except b.BackendError:
                pass
            if broker.poll() is not None or time.monotonic()>deadline:
                raise RuntimeError("broker did not become ready")
            time.sleep(.1)
        evidence["cases"]["unauthorized_inference"]={"http_status":status,"admitted_calls":count_admissions(),"pass":status==401 and count_admissions()==0}
        db=private/"timer.sqlite3"
        Runtime.initialize(db,SyntheticConfig(expires_at=time.time()+600,max_events=1,interval_seconds=5))
        timer=start("timer",["-m","resident_initiative","run","--db",str(db),"--backend-config",str(config_path),"--max-seconds","100"])
        timer.wait(timeout=110)
        first=state(db)
        assert timer.returncode==0 and len(first["proposals"])==1, "real timer/model did not produce one proposal"
        proposal=first["proposals"][0]
        assert proposal["provider_evidence"]==b.AuthenticatedBackend.evidence_class
        assert not proposal["contact_authorized"] and not proposal["execution_authorized"]
        before=count_admissions()
        restart=start("timer-restart",["-m","resident_initiative","run","--db",str(db),"--backend-config",str(config_path),"--max-seconds","2"])
        restart.wait(timeout=10)
        assert restart.returncode==0 and state(db)["proposals"]==first["proposals"] and count_admissions()==before
        evidence["cases"]["real_timer_restart"]={"pass":True,"proposals":1,"new_inference_on_restart":0,"proposal_id":proposal["proposal_id"],"provider_evidence":proposal["provider_evidence"]}
        runtime=Runtime(db)
        try:
            fake=private/"unissued-grant.json"
            fake.write_text(canonical({"scope":"LOCAL_SYNTHETIC_HANDOFF_ONLY","grant_id":"unissued"}),encoding="utf-8")
            output=private/"handoff"
            try:
                runtime.export(proposal["proposal_id"],fake,output)
                raise AssertionError("unissued grant exported")
            except PermissionError:
                assert not output.exists()
            grant=runtime.grant_local(proposal["proposal_id"],output,expires_at=time.time()+120)
            grant_path=private/"local-grant.json"
            grant_path.write_text(canonical(grant),encoding="utf-8")
            exported=runtime.export(proposal["proposal_id"],grant_path,output)
            assert runtime.export(proposal["proposal_id"],grant_path,output)==exported
            assert len(list(output.glob("*.json")))==1
            evidence["cases"]["local_handoff_gate"]={"pass":True,"unauthorized_rejected":True,"artifacts_after_replay":1,"sha256":exported["sha256"],"scope":exported["scope"]}
            runtime.cancel()
            assert runtime.cycle()["state"]=="CANCELLED"
        finally:
            runtime.close()
        cancelled=start("cancelled-restart",["-m","resident_initiative","run","--db",str(db),"--backend-config",str(config_path),"--max-seconds","2"])
        cancelled.wait(timeout=10)
        assert cancelled.returncode==0 and count_admissions()==before and state(db)["state"]=="CANCELLED"
        evidence["cases"]["cancel_restart"]={"pass":True,"state":"CANCELLED","additional_inference":0}
        # Real unavailable TCP endpoint, followed by restart with the same durable
        # event and the authenticated available broker. No message transport exists.
        offline=dict(cfg,port=unused_port())
        offline_path=private/"offline-backend.json"
        offline_path.write_text(canonical(offline),encoding="utf-8")
        recovery_db=private/"recovery.sqlite3"
        Runtime.initialize(recovery_db,SyntheticConfig(expires_at=time.time()+600,max_events=1,interval_seconds=5))
        down=start("network-down",["-m","resident_initiative","run","--db",str(recovery_db),"--backend-config",str(offline_path),"--max-seconds","3"])
        down.wait(timeout=10)
        down_state=state(recovery_db)
        assert down.returncode==0 and not down_state["proposals"] and any(r["disposition"]=="DEFERRED_MODEL_FAILURE" for r in down_state["receipts"])
        up=start("network-recovered",["-m","resident_initiative","run","--db",str(recovery_db),"--backend-config",str(config_path),"--max-seconds","100"])
        up.wait(timeout=110)
        recovered=state(recovery_db)
        assert up.returncode==0 and len(recovered["proposals"])==1
        evidence["cases"]["network_restart_recovery"]={"pass":True,"proposals_while_down":0,"proposals_after_recovery":1,"durable_failure_receipt":True}
        evidence["model_admissions"]=count_admissions()
        evidence["status"]="PASS"
    except BaseException as exc:
        evidence["status"]="FAILED"
        evidence["error_type"]=type(exc).__name__
        evidence["error"]=str(exc)
        raise
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=5)
        for output in files:
            output.close()
        evidence["finished_at"]=time.time()
        evidence["processes_stopped"]=all(c.poll() is not None for c in children)
        evidence["process_exit_codes"]=[c.returncode for c in children]
        (private/"QUALIFICATION.json").write_text(canonical(evidence)+"\n",encoding="utf-8")
        print(canonical({"status":evidence["status"],"cases":evidence["cases"],"phone_sends":0,"processes_stopped":evidence["processes_stopped"]}))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
