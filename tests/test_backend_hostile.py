"""Independent negative probes for the local initiative inference boundary.

Only ephemeral loopback listeners and temporary trial databases are used.
The model collaborator is synthetic; these are not live inference receipts.
"""
import json
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from resident_initiative import deps
from resident_initiative import backend as b
from pre_active.engine import RetryableModelError


class HostileBackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.key = secrets.token_bytes(32)
        self.calls = 0
        self.cfg = {
            "schema": b.SCHEMA, "port": 0, "model": "synthetic-model",
            "key": self.key,
            "token_file": str(Path(self.temporary.name) / "key"),
            "broker_state": str(Path(self.temporary.name) / "state.sqlite3"),
            "timeout_seconds": 1, "max_tokens": 32,
            "expires_at": time.time() + 120, "max_calls": 3,
        }
        self.broker = b.Broker(self.cfg, inference=self.infer)
        self.thread = threading.Thread(
            target=self.broker.serve_forever,
            kwargs={"poll_interval": 0.01}, daemon=True,
        )
        self.thread.start()
        self.port = self.broker.server_address[1]

    def tearDown(self):
        self.broker.shutdown()
        self.broker.server_close()
        self.thread.join(2)
        self.temporary.cleanup()

    def infer(self, messages, cfg):
        self.calls += 1
        return '{"message":"Synthetic diagnostic.","reason":"Test fixture."}'

    def request(self, raw=None):
        if raw is None:
            raw = b.canonical({
                "nonce": secrets.token_hex(16), "issued_at": time.time(),
                "messages": [{"role": "user", "content": "synthetic"}],
            })
        return b._post(self.port, "/v1/evaluate", raw, {
            "Content-Type": "application/json",
            "X-Initiative-MAC": b._mac(self.key, b"REQUEST\n", raw),
        }, 1)

    def client(self):
        return b.AuthenticatedBackend(
            port=self.port, key=self.key,
            model="synthetic-model", timeout_seconds=1,
        )

    def test_slow_header_connections_are_capped_and_expire_despite_drip(self):
        # Four incomplete requests use the declared finite admission slots.
        # Continued bytes arrive well inside the per-operation socket timeout;
        # only a whole-admission deadline can recover these slots in time.
        sockets = []
        started = time.monotonic()
        try:
            for _ in range(4):
                conn = socket.create_connection(("127.0.0.1", self.port), 1)
                conn.settimeout(0.1)
                conn.sendall(
                    b"POST /v1/evaluate HTTP/1.1\r\nHost: localhost\r\nX-Slow: "
                )
                sockets.append(conn)
            time.sleep(0.1)
            excess_started = time.monotonic()
            with self.assertRaises(b.BackendError):
                self.request()
            self.assertLess(time.monotonic() - excess_started, 1.5)
            self.assertEqual(self.calls, 0)

            pending = list(sockets)
            while pending and time.monotonic() - started < 4.5:
                for conn in list(pending):
                    try:
                        conn.sendall(b"a")
                        received = conn.recv(1)
                        if received == b"":
                            pending.remove(conn)
                    except socket.timeout:
                        pass
                    except OSError:
                        pending.remove(conn)
                time.sleep(0.1)
            self.assertEqual(len(pending), 0, "slow clients retained admission slots")
            self.assertLess(time.monotonic() - started, 4.8)
            self.assertEqual(self.calls, 0)
        finally:
            for conn in sockets:
                conn.close()
        # Capacity must recover for a legitimate authenticated request.
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.calls, 1)

    def test_refused_connection_is_typed_and_client_marks_retryable(self):
        # Reserve a real local port without listening: connect must refuse.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            refused_port = reserved.getsockname()[1]
            with self.assertRaises(b.BackendError):
                b._post(refused_port, "/v1/evaluate", b"{}", {}, 0.3)
            client = b.AuthenticatedBackend(
                port=refused_port, key=self.key,
                model="synthetic-model", timeout_seconds=0.3,
            )
            with self.assertRaises(RetryableModelError):
                client.respond(messages=[{"role": "user", "content": "synthetic"}], tools=[])
        self.assertEqual(self.calls, 0)

    def test_authenticated_duplicate_json_and_nonfinite_fields_rejected(self):
        messages = json.dumps([{"role": "user", "content": "synthetic"}])
        bad_requests = [
            ('{"nonce":"' + "a" * 32 + '","nonce":"' + "b" * 32
             + '","issued_at":' + str(time.time()) + ',"messages":' + messages + '}'),
            ('{"nonce":"' + "c" * 32 + '","issued_at":NaN,"messages":' + messages + '}'),
        ]
        for raw in bad_requests:
            with self.subTest(raw=raw):
                self.assertEqual(self.request(raw.encode())[0], 502)
        self.assertEqual(self.calls, 0)

    def test_malformed_provider_roots_have_typed_rejection(self):
        bad = [None, [], 1, "invalid", {"message": None}, {"message": []}]
        for value in bad:
            with self.subTest(value=value), patch.object(
                b, "_post", return_value=(200, {}, b.canonical(value))
            ):
                with self.assertRaises(b.BackendError):
                    b.ollama_inference([{"role": "user", "content": "synthetic"}], self.cfg)
        self.assertEqual(self.calls, 0)

    def test_authenticated_response_for_other_nonce_is_rejected(self):
        def unrelated_response(port, path, body, headers, timeout):
            nonce = json.loads(body)["nonce"]
            other = ("0" if nonce[0] != "0" else "1") + nonce[1:]
            raw = b.canonical({
                "schema": b.SCHEMA, "model": "synthetic-model",
                "text": "synthetic reply", "done": True,
            })
            signature = b._mac(self.key, b"RESPONSE\n" + other.encode() + b"\n", raw)
            return 200, {"X-Initiative-MAC": signature}, raw
        with patch.object(b, "_post", side_effect=unrelated_response):
            with self.assertRaises(RetryableModelError):
                self.client().respond(
                    messages=[{"role": "user", "content": "synthetic"}], tools=[]
                )
        self.assertEqual(self.calls, 0)

    def test_failed_inferences_still_consume_finite_call_budget(self):
        def failed_model(messages, cfg):
            self.calls += 1
            raise b.BackendError("synthetic provider unavailable")
        self.broker.inference = failed_model
        for _ in range(3):
            self.assertEqual(self.request()[0], 502)
        self.assertEqual(self.request()[0], 429)
        self.assertEqual(self.calls, 3)


if __name__ == "__main__":
    unittest.main()
