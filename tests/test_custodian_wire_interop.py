"""Exact Python custodian v1 wire/proposal integration in disposable process memory.

No socket, Windows service, protected ACL, recipient or host deployment is tested.
The fake transport only translates byte JSON to the actual sibling service
handler. A separate Windows IPC + ACL test is required for qualification.
"""
import importlib.util
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from resident_initiative.runtime import Runtime, SyntheticConfig, canonical
from resident_initiative.stop_authority import StopAuthorityUnavailable
from resident_initiative.stop_pipe_client import CustodianPipeClient
from pre_active.engine import ModelResponse


SERVICE_SOURCE = Path(os.environ.get(
    "OBSESSION_CUSTODIAN_SOURCE",
    str(Path(__file__).resolve().parents[1] / "experiments" / "stop_custodian_service" / "stop_custodian.py"),
))


class _Provider:
    def respond(self, *, messages, tools):
        return ModelResponse(final_text=canonical({"message": "Fixture diagnostic", "reason": "Fixture bounded clock"}))


class _WireConnection:
    def __init__(self, service):
        self.service = service
        self.out = None

    def send_bytes(self, raw):
        try:
            result = self.service.handle(self.service_module.exact_json(raw))
            response = {"ok": True, "result": result}
        except (ValueError, PermissionError, OSError) as exc:
            response = {"ok": False, "error": type(exc).__name__ + ":" + str(exc)}
        self.out = self.service_module.canonical(response)

    def recv_bytes(self, max_length):
        if self.out is None or len(self.out) > max_length:
            raise ValueError("missing/oversized response")
        return self.out

    def close(self):
        return None


class CustodianWireInteropTests(unittest.TestCase):
    def test_python_protocol_exact_signed_grant_publish_and_durable_stop(self):
        self.assertTrue(SERVICE_SOURCE.is_file(), f"required custodian source missing: {SERVICE_SOURCE}")
        spec = importlib.util.spec_from_file_location("custodian_wire_v1", SERVICE_SOURCE)
        service_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(service_module)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            protected = root / "synthetic_host_custody"
            protected.mkdir()
            service_module.Custodian.initialize(protected)
            operator_key = b"test-only-operator-secret-32-bytes!!"
            transport_key = b"test-only-transport-secret-32bytes"
            service = service_module.Custodian(protected, operator_key, clock=lambda: 100.0)
            keyfile = root / "test-transport.key"
            keyfile.write_bytes(transport_key)
            adapter = CustodianPipeClient(
                authkey_file=keyfile, output_root=protected / "outbox",
                pipe_name=str(root / "synthetic-ipc.sock"), family="AF_UNIX", allow_test_unix=True)

            def fake_client(address, *, family, authkey):
                self.assertEqual(address, str(root / "synthetic-ipc.sock"))
                self.assertEqual(family, "AF_UNIX")
                self.assertEqual(authkey, transport_key)
                connection = _WireConnection(service)
                connection.service_module = service_module
                return connection

            db = root / "resident.sqlite3"
            Runtime.initialize(db, SyntheticConfig(expires_at=500, interval_seconds=30, max_events=2), now=100)
            with mock.patch("resident_initiative.stop_pipe_client.Client", side_effect=fake_client):
                runtime = Runtime(db, _Provider(), clock=lambda: 100.0, stop_authority=adapter)
                try:
                    runtime.cycle()
                    runtime.cycle()
                    proposal = runtime.status()["proposals"][0]
                    generation = runtime.generation
                    service.handle(service_module.make_operator_request(operator_key, "REGISTER", generation=generation))
                    grant = runtime.grant_local(proposal["proposal_id"], protected / "outbox", expires_at=200)
                    host_request = grant["host_grant_request"]
                    issued = service.handle(service_module.make_operator_request(
                        operator_key, "GRANT", generation=generation,
                        artifact_id=host_request["artifact_id"], source_digest=host_request["source_digest"],
                        expires_at=host_request["expires_at"]))
                    self.assertEqual(issued["grant"], host_request)
                    grant["host_grant_mac"] = issued["grant_mac"]
                    grant_path = root / "test-signed-grant.json"
                    grant_path.write_text(canonical(grant), encoding="utf-8")
                    first = runtime.export(proposal["proposal_id"], grant_path, protected / "outbox")
                    self.assertEqual(hashlib.sha256(Path(first["path"]).read_bytes()).hexdigest(), first["sha256"])
                    self.assertEqual(len(list((protected / "outbox").glob("*.json"))), 1)
                    second = runtime.export(proposal["proposal_id"], grant_path, protected / "outbox")
                    self.assertEqual(second["sha256"], first["sha256"])
                    service.handle(service_module.make_operator_request(operator_key, "REVOKE", generation=generation))
                    with self.assertRaisesRegex(StopAuthorityUnavailable, "CUSTODIAN_PUBLICATION_UNVERIFIED"):
                        runtime.export(proposal["proposal_id"], grant_path, protected / "outbox")
                    # Closing/restarting service from protected journal retains STOP.
                    reloaded = service_module.Custodian(protected, operator_key, clock=lambda: 100.0)
                    self.assertIs(reloaded.generations[generation], False)
                finally:
                    runtime.close()


if __name__ == "__main__":
    unittest.main()
