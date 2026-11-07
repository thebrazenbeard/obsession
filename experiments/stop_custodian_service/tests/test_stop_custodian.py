"""Synthetic tests. No protected host ACL or actual contact is exercised."""
from __future__ import annotations

import base64
import hashlib
import multiprocessing
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from stop_custodian import (Custodian, CustodyDenied, canonical, exact_json,
                            make_operator_request, request, serve)


class Clock:
    value = 1000.0
    def __call__(self):
        return self.value


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stopcust-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = Clock()
        self.operator_key = secrets.token_bytes(32)
        self.transport_key = secrets.token_bytes(32)
        Custodian.initialize(self.root)
        self.c = Custodian(self.root, self.operator_key, clock=self.clock)
        self.generation = "synthetic_gen_20261107"
        self.artifact = hashlib.sha256(b"artifact1").hexdigest()
        self.body = {
            "schema": "initiative.local-handoff.v1",
            "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY",
            "proposal_digest": "sha256:synthetic",
            "proposal": {
                "generation": self.generation,
                "target_class": "SYNTHETIC_LOCAL_ONLY",
                "contact_authorized": False,
                "delivery_verified": False,
                "execution_authorized": False,
            },
            "contact_authorized": False,
            "delivery_verified": False,
        }
        self.payload = canonical(self.body)
        self.source_digest = hashlib.sha256(self.payload).hexdigest()

    def operator(self, op, **fields):
        return make_operator_request(self.operator_key, op, **fields)

    def register(self):
        return self.c.handle(self.operator("REGISTER", generation=self.generation))

    def grant(self):
        return self.c.handle(self.operator("GRANT", generation=self.generation,
                                           artifact_id=self.artifact, source_digest=self.source_digest,
                                           expires_at=self.clock.value + 300))

    def publish_args(self, grant_result=None, payload=None):
        g = grant_result or self.grant()
        body = self.payload if payload is None else payload
        return {"op": "PUBLISH", "generation": self.generation,
                "artifact_id": self.artifact, "source_digest": self.source_digest,
                "payload_b64": base64.b64encode(body).decode("ascii"),
                "now": self.clock.value, "grant": g["grant"], "grant_mac": g["grant_mac"]}

    def test_bootstrap_is_one_shot_and_missing_journal_fails_closed(self):
        with self.assertRaises(CustodyDenied):
            Custodian.initialize(self.root)
        journal = self.root / "private" / "stop-journal.jsonl"
        journal.rename(self.root / "private" / "renamed.jsonl")
        with self.assertRaises(CustodyDenied):
            Custodian(self.root, self.operator_key, clock=self.clock)

    def test_register_grant_publish_idempotent_and_revoke_survives_restart(self):
        self.register()
        grant = self.grant()
        req = self.publish_args(grant)
        first = self.c.publish(req)
        self.assertEqual(first["state"], "PUBLISHED")
        self.assertTrue(Path(first["path"]).is_file())
        self.assertEqual(self.c.publish(req)["state"], "ALREADY_IDENTICAL")
        self.assertEqual(self.c.revoke(self.operator("REVOKE", generation=self.generation))["state"], "REVOKED")
        with self.assertRaises(CustodyDenied):
            self.c.publish(req)
        restarted = Custodian(self.root, self.operator_key, clock=self.clock)
        with self.assertRaises(CustodyDenied):
            restarted.publish(req)
        with self.assertRaises(CustodyDenied):
            restarted.register(self.operator("REGISTER", generation=self.generation))

    def test_bad_grant_and_bad_contact_payload_denied_without_artifact(self):
        self.register()
        grant = self.grant()
        req = self.publish_args(grant)
        req["grant_mac"] = "0" * 64
        with self.assertRaises(CustodyDenied):
            self.c.publish(req)
        bad_payload = canonical({**self.body, "contact_authorized": True})
        with self.assertRaises(CustodyDenied):
            self.c.publish(self.publish_args(grant, bad_payload))
        self.assertEqual(list((self.root / "outbox").iterdir()), [])

    def test_digest_domain_and_operator_role_separation(self):
        self.register()
        grant = self.grant()
        request_body = self.publish_args(grant)
        request_body["source_digest"] = hashlib.sha256(b"proposal-only").hexdigest()
        with self.assertRaises(CustodyDenied):
            self.c.publish(request_body)
        # A consumer who knows only the transport key cannot forge a distinct
        # operator-key HMAC; the request must be rejected before journaling.
        weak = make_operator_request(self.transport_key, "REVOKE", generation=self.generation)
        with self.assertRaises(CustodyDenied):
            self.c.revoke(weak)
        self.assertEqual(self.c.generations[self.generation], True)

    def test_grant_operator_nonce_consumed_across_restart(self):
        self.register()
        signed = self.operator("GRANT", generation=self.generation,
                               artifact_id=self.artifact, source_digest=self.source_digest,
                               expires_at=self.clock.value + 300)
        self.assertIn("grant_mac", self.c.grant(signed))
        with self.assertRaises(CustodyDenied):
            self.c.grant(signed)
        restarted = Custodian(self.root, self.operator_key, clock=self.clock)
        with self.assertRaises(CustodyDenied):
            restarted.grant(signed)

    def test_duplicate_json_and_nonfinite_values_rejected(self):
        with self.assertRaises(CustodyDenied):
            exact_json(b'{"op":"PUBLISH","op":"REGISTER"}')
        with self.assertRaises(CustodyDenied):
            exact_json(b'{"now":NaN}')

    def test_expired_grant_and_missing_registration_fail_closed(self):
        with self.assertRaises(CustodyDenied):
            self.c.publish(self.publish_args({"grant": {}, "grant_mac": "0" * 64}))
        self.register()
        req = self.publish_args(self.grant())
        self.clock.value += 400
        with self.assertRaises(CustodyDenied):
            self.c.publish(req)
        self.assertEqual(list((self.root / "outbox").iterdir()), [])

    def test_corrupted_journal_denies_on_restart(self):
        self.register()
        journal = self.root / "private" / "stop-journal.jsonl"
        with journal.open("ab") as f:
            f.write(b"broken")
        with self.assertRaises(CustodyDenied):
            Custodian(self.root, self.operator_key, clock=self.clock)

    def test_revoke_waits_for_server_owned_publication(self):
        self.register()
        req = self.publish_args(self.grant())
        entered, resume, revoked = threading.Event(), threading.Event(), threading.Event()
        errors = []
        original_link = os.link

        def delayed_link(src, dest):
            entered.set()
            if not resume.wait(3):
                raise TimeoutError("test barrier")
            return original_link(src, dest)

        def publication():
            try:
                self.c.publish(req)
            except BaseException as exc:
                errors.append(exc)

        def stop():
            try:
                self.c.revoke(self.operator("REVOKE", generation=self.generation))
            except BaseException as exc:
                errors.append(exc)
            revoked.set()

        with patch("stop_custodian.os.link", side_effect=delayed_link):
            writer = threading.Thread(target=publication)
            writer.start()
            self.assertTrue(entered.wait(3))
            stopper = threading.Thread(target=stop)
            stopper.start()
            self.assertFalse(revoked.wait(.05), "STOP returned before protected publication finished")
            resume.set()
            writer.join(3)
            stopper.join(3)
        self.assertFalse(writer.is_alive())
        self.assertFalse(stopper.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(revoked.is_set())
        with self.assertRaises(CustodyDenied):
            self.c.publish(req)


@unittest.skipUnless(os.name == "posix", "AF_UNIX isolated server test")
class ProcessTransport(Fixture):
    def test_separate_process_raw_bytes_without_socket(self):
        child_end, parent_end = multiprocessing.Pipe(duplex=True)
        self.addCleanup(child_end.close)
        self.addCleanup(parent_end.close)

        def run_worker(conn, root, operator_key):
            state = Custodian(root, operator_key)
            try:
                while True:
                    try:
                        body = exact_json(conn.recv_bytes(16384))
                    except EOFError:
                        return
                    if body == {"op": "SHUTDOWN_TEST"}:
                        return
                    try:
                        reply = {"ok": True, "result": state.handle(body)}
                    except CustodyDenied as exc:
                        reply = {"ok": False, "error": str(exc)}
                    conn.send_bytes(canonical(reply))
            finally:
                conn.close()

        child = multiprocessing.Process(target=run_worker, args=(child_end, str(self.root), self.operator_key))
        child.start()
        self.addCleanup(lambda: child.terminate() if child.is_alive() else None)
        child_end.close()
        try:
            parent_end.send_bytes(canonical(self.operator("REGISTER", generation=self.generation)))
            result = exact_json(parent_end.recv_bytes(16384))
            self.assertTrue(result["ok"])
            parent_end.send_bytes(canonical(self.operator("REVOKE", generation=self.generation)))
            result = exact_json(parent_end.recv_bytes(16384))
            self.assertEqual(result["result"]["state"], "REVOKED")
            parent_end.send_bytes(canonical({"op": "SHUTDOWN_TEST"}))
        finally:
            parent_end.close()
            child.join(3)
        self.assertFalse(child.is_alive())

    @unittest.skipUnless(os.environ.get("OBSESSION_ALLOW_REAL_IPC_TEST") == "1",
                         "AF_UNIX listener requires socket permission; opt in on qualified test host")
    def test_actual_separate_process_json_protocol(self):
        address = str(self.root / "socket")
        child = multiprocessing.Process(target=serve, kwargs={"root": str(self.root), "address": address,
                "family": "AF_UNIX", "transport_key": self.transport_key, "operator_key": self.operator_key})
        child.start()
        self.addCleanup(lambda: child.terminate() if child.is_alive() else None)
        for _ in range(50):
            if Path(address).exists():
                break
            time.sleep(.02)
        self.assertTrue(Path(address).exists(), "server IPC not present")
        try:
            registered = request(address, "AF_UNIX", self.transport_key,
                                 self.operator("REGISTER", generation=self.generation))
            self.assertEqual(registered["state"], "REGISTERED")
            gr = request(address, "AF_UNIX", self.transport_key,
                         self.operator("GRANT", generation=self.generation,
                                       artifact_id=self.artifact, source_digest=self.source_digest,
                                       expires_at=time.time() + 300))
            published = request(address, "AF_UNIX", self.transport_key, self.publish_args(gr))
            self.assertEqual(published["state"], "PUBLISHED")
            self.assertTrue(Path(published["path"]).is_file())
            revoked = request(address, "AF_UNIX", self.transport_key,
                              self.operator("REVOKE", generation=self.generation))
            self.assertEqual(revoked["state"], "REVOKED")
            with self.assertRaises(CustodyDenied):
                request(address, "AF_UNIX", self.transport_key, self.publish_args(gr))
        finally:
            child.terminate()
            child.join(3)
        with self.assertRaises((OSError, EOFError, ConnectionError)):
            request(address, "AF_UNIX", self.transport_key, self.publish_args(gr))


if __name__ == "__main__":
    unittest.main()
