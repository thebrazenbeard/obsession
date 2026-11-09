"""Pure source/wire tests; not a Windows ACL or service qualification."""

import base64
import ast
import hashlib
import json
import unittest
from pathlib import Path

from resident_initiative.native_stop_pipe_client import (
    NativeNamedPipeChannel, NativeStopDenied, NativeStopPublishClient,
    PUBLISH_PIPE, encode_publish, frame, validate_handoff,
)


GENERATION = "generation_valid_20261107"
ARTIFACT = "a" * 64


def payload():
    return (json.dumps({
        "schema": "initiative.local-handoff.v1",
        "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY",
        "proposal_digest": "sha256:" + "b" * 64,
        "proposal": {"schema": "initiative.proposal.v1",
                     "target_class": "SYNTHETIC_LOCAL_ONLY",
                     "execution_authorized": False,
                     "contact_authorized": False,
                     "delivery_verified": False,
                     "message": "Synthetic local test only"},
        "delivery_verified": False, "contact_authorized": False,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class FakeChannel:
    def __init__(self, reply=None, *, available=True, error=None):
        self.reply = reply if reply is not None else ("PUBLISHED|" + ARTIFACT).encode()
        self.available = available
        self.error = error
        self.requests = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.closed = True

    def send_bytes(self, message):
        self.requests.append(message)

    def poll(self, timeout):
        assert 0 < timeout <= 10
        return self.available

    def recv_bytes(self, maxlength):
        assert maxlength == 4096
        if self.error is not None:
            raise self.error
        return self.reply


class FakeOverlapped:
    def __init__(self, content):
        self.content = content

    def GetOverlappedResult(self, _wait):
        return len(self.content), 0

    def getbuffer(self):
        return memoryview(self.content)


class FakeWinApi:
    ERROR_IO_PENDING = 997

    def __init__(self, response):
        self.response = bytearray(response)
        self.writes = []

    def WriteFile(self, handle, data, *, overlapped):
        assert handle == "fake-handle" and overlapped is True
        self.writes.append(data)
        return FakeOverlapped(data), 0

    def ReadFile(self, handle, n, *, overlapped):
        assert handle == "fake-handle" and overlapped is True
        chunk = bytes(self.response[:n])
        del self.response[:n]
        return FakeOverlapped(chunk), 0

    def PeekNamedPipe(self, handle):
        assert handle == "fake-handle"
        return (len(self.response), 0)


def grant(p):
    return {"generation": GENERATION, "artifact_id": ARTIFACT,
            "source_digest": hashlib.sha256(p).hexdigest(),
            "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "expires_at": 200.0}


class NativePipeTests(unittest.TestCase):
    def setUp(self):
        self.payload = payload()
        self.digest = hashlib.sha256(self.payload).hexdigest()
        self.grant = grant(self.payload)
        self.fake = FakeChannel()
        self.calls = []

    def client(self, fake=None):
        def connect(pipe):
            self.calls.append(pipe)
            return self.fake if fake is None else fake
        return NativeStopPublishClient(connector=connect)

    def publish(self, client=None, **overrides):
        args = dict(generation=GENERATION, artifact_id=ARTIFACT,
                    source_digest=self.digest, payload=self.payload,
                    grant=self.grant, now=100.0)
        args.update(overrides)
        return (client or self.client()).publish_local(**args)

    def test_wire_exact_utf8_and_native_four_byte_frame(self):
        raw = encode_publish(GENERATION, ARTIFACT, self.payload)
        expected = (b"PUBLISH|" + GENERATION.encode() + b"|" + ARTIFACT.encode()
                    + b"|" + base64.b64encode(self.payload) + b"|V1")
        self.assertEqual(raw, expected)
        self.assertEqual(frame(raw), len(expected).to_bytes(4, "big") + expected)
        self.assertEqual(len(frame(raw)), len(raw) + 4)

    def test_actual_gate_handoff_payload_uses_typed_proposal_digest(self):
        # Load the exact production method AST without importing unrelated
        # resident dependencies. This catches schema drift against gate.py.
        gate_path = Path(__file__).resolve().parents[1] / "resident_initiative" / "gate.py"
        tree = ast.parse(gate_path.read_text(encoding="utf-8"))
        original = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "LocalHandoffGate")
        method = next(n for n in original.body if isinstance(n, ast.FunctionDef) and n.name == "_handoff_payload")
        fixture = ast.ClassDef(name="FixtureGate", bases=[], keywords=[], body=[method], decorator_list=[])
        module = ast.fix_missing_locations(ast.Module(body=[fixture], type_ignores=[]))
        globals_ = {"canonical": lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)}
        exec(compile(module, str(gate_path), "exec"), globals_)
        payload_from_gate = globals_["FixtureGate"]._handoff_payload(
            {"proposal_digest": "sha256:" + "b" * 64}, json.loads(self.payload)["proposal"])
        self.assertEqual(validate_handoff(payload_from_gate)["proposal_digest"], "sha256:" + "b" * 64)
        self.assertEqual(encode_publish(GENERATION, ARTIFACT, payload_from_gate).split(b"|")[0], b"PUBLISH")

    def test_reject_untyped_or_malformed_proposal_digest(self):
        for value in ("b" * 64, "sha256:" + "b" * 63, "SHA256:" + "b" * 64,
                      "sha256:" + "g" * 64, None, 123):
            document = json.loads(self.payload)
            document["proposal_digest"] = value
            corrupted = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with self.subTest(value=value), self.assertRaises(NativeStopDenied):
                validate_handoff(corrupted)

    def test_raw_win32_byte_transport_explicit_framing(self):
        message = encode_publish(GENERATION, ARTIFACT, self.payload)
        response = ("PUBLISHED|" + ARTIFACT).encode()
        api = FakeWinApi(frame(response))
        channel = NativeNamedPipeChannel(PUBLISH_PIPE)
        channel.api = api
        channel.handle = "fake-handle"
        channel.send_bytes(message)
        self.assertEqual(api.writes, [frame(message)])
        self.assertTrue(channel.poll(0.05))
        self.assertEqual(channel.recv_bytes(4096), response)
        self.assertEqual(api.response, bytearray())

    def test_raw_win32_transport_rejects_oversized_response_length(self):
        api = FakeWinApi((9000).to_bytes(4, "big"))
        channel = NativeNamedPipeChannel(PUBLISH_PIPE)
        channel.api = api
        channel.handle = "fake-handle"
        with self.assertRaises(ValueError):
            channel.recv_bytes(4096)

    def test_valid_receipt_requires_same_artifact(self):
        result = self.publish()
        self.assertEqual(result["receipt"], "PUBLISHED|" + ARTIFACT)
        self.assertTrue(result["path"].endswith("\\output\\" + ARTIFACT + ".json"))
        self.assertEqual(self.calls, [PUBLISH_PIPE])
        self.assertEqual(self.fake.requests, [encode_publish(GENERATION, ARTIFACT, self.payload)])
        self.assertTrue(self.fake.closed)

    def test_idempotent_response_only_exact_artifact(self):
        self.publish(self.client(FakeChannel(("ALREADY_PRESENT|" + ARTIFACT).encode())))
        with self.assertRaisesRegex(NativeStopDenied, "UNEXPECTED_CUSTODIAN_RESPONSE"):
            self.publish(self.client(FakeChannel(("PUBLISHED|" + "c" * 64).encode())))

    def test_server_hold_never_promoted_to_success(self):
        with self.assertRaisesRegex(NativeStopDenied, "STOP_ACTIVE"):
            self.publish(self.client(FakeChannel(b"HOLD|STOP_ACTIVE_OR_UNVERIFIED")))

    def test_timeout_eof_invalid_utf8_denied(self):
        cases = [FakeChannel(available=False), FakeChannel(error=EOFError()),
                 FakeChannel(b"\xff"), FakeChannel(b"GRANTED|" + ARTIFACT.encode())]
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(NativeStopDenied):
                    self.publish(self.client(candidate))

    def test_digest_grant_and_expiry_fail_before_transport(self):
        cases = [{"source_digest": "b" * 64}, {"grant": {**self.grant, "artifact_id": "c" * 64}},
                 {"now": 201.0}, {"grant_mac": "python-hmac-is-not-native-authorization"}]
        for changes in cases:
            with self.subTest(changes=changes):
                self.calls.clear()
                with self.assertRaises(NativeStopDenied):
                    self.publish(**changes)
                self.assertFalse(self.calls)

    def test_contact_and_execution_payload_rejected_before_transport(self):
        for key, value in [("contact_authorized", True), ("delivery_verified", True)]:
            document = json.loads(self.payload)
            document[key] = value
            corrupted = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with self.subTest(key=key), self.assertRaises(NativeStopDenied):
                validate_handoff(corrupted)
        document = json.loads(self.payload)
        document["proposal"]["execution_authorized"] = True
        corrupted = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with self.assertRaises(NativeStopDenied):
            validate_handoff(corrupted)

    def test_duplicate_json_nan_and_trailing_payload_denied(self):
        with self.assertRaises(NativeStopDenied):
            validate_handoff(b'{"schema":1,"schema":2}\n')
        with self.assertRaises(NativeStopDenied):
            validate_handoff(b'{"schema":NaN}\n')
        with self.assertRaises(NativeStopDenied):
            validate_handoff(self.payload[:-1])

    def test_no_operator_endpoint_selection(self):
        with self.assertRaises(ValueError):
            NativeStopPublishClient(pipe=r"\\.\pipe\VeraObsessionStopOperatorV1")
        client = self.client()
        with self.assertRaisesRegex(NativeStopDenied, "OPERATOR_STOP_REQUIRED"):
            client.revoke(generation=GENERATION, now=100.0)
        with self.assertRaisesRegex(NativeStopDenied, "LEGACY_STOP_LEASE_UNSUPPORTED"):
            client.hold_active(generation=GENERATION, now=100.0)
        self.assertFalse(self.calls)

    def test_pipe_open_failure_is_hold(self):
        def fail(_pipe):
            raise FileNotFoundError("no live service")
        with self.assertRaisesRegex(NativeStopDenied, "CUSTODIAN_PIPE_UNAVAILABLE"):
            self.publish(NativeStopPublishClient(connector=fail))


if __name__ == "__main__":
    unittest.main()

