"""Qwen3.5 Ollama protocol and authenticated non-content failure reporting.

All model responses are synthetic; no real Ollama process is contacted.
"""
import json
from pathlib import Path
import secrets
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


class OllamaDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.private = Path(self.tmp.name)
        self.key = secrets.token_bytes(32)
        (self.private / "token").write_text(self.key.hex(), encoding="ascii")
        self.cfg = {"schema": b.SCHEMA, "port": 23456, "model": "qwen3.5:0.8b",
            "token_file": str(self.private / "token"),
            "broker_state": str(self.private / "state.sqlite3"),
            "timeout_seconds": 2, "max_tokens": 256,
            "expires_at": time.time() + 120, "max_calls": 3}
        self.messages = [{"role": "user", "content": "fixture prompt kept private"}]

    def tearDown(self):
        self.tmp.cleanup()

    def load(self, changes=None):
        cfg = dict(self.cfg)
        cfg.update(changes or {})
        path = self.private / "config.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        return b.load_config(path)

    def fake_ollama(self, changes=None):
        value = {"model": "qwen3.5:0.8b", "done": True,
                 "done_reason": "stop", "message": {"role": "assistant", "content": "{}"}}
        value.update(changes or {})
        return b.canonical(value)

    def test_default_does_not_modify_thinking_but_exact_opt_in_does(self):
        requests = []

        def fake_post(_port, _path, body, _headers, _timeout):
            requests.append(json.loads(body))
            return 200, {}, self.fake_ollama()

        with patch.object(b, "_post", side_effect=fake_post):
            self.assertEqual(b.ollama_inference(self.messages, self.load()), "{}")
            self.assertEqual(b.ollama_inference(self.messages, self.load({"qwen35_08b_think_false": True})), "{}")
        self.assertNotIn("think", requests[0])
        self.assertIs(requests[1]["think"], False)
        self.assertEqual(requests[0]["options"], requests[1]["options"])
        self.assertEqual(requests[0]["messages"], requests[1]["messages"])
        self.assertEqual(requests[0]["options"]["seed"], 20261106)

    def test_thinking_override_is_exact_target_and_boolean_only(self):
        self.assertFalse(self.load({"qwen35_08b_think_false": False})["qwen35_08b_think_false"])
        for changes in (
            {"model": "qwen2.5:3b", "qwen35_08b_think_false": True},
            {"model": "qwen3.5:4b", "qwen35_08b_think_false": True},
            {"qwen35_08b_think_false": 1},
            {"qwen35_08b_think_false": "false"},
            {"think": False},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.load(changes)

    def test_200_length_thinking_without_content_is_classified_without_leak(self):
        sensitive = "PRIVATE_THOUGHT_TOKEN_AND_CONTENT"
        raw = self.fake_ollama({"done_reason": "length", "message": {
            "role": "assistant", "content": "", "thinking": sensitive}})
        with patch.object(b, "_post", return_value=(200, {}, raw)):
            with self.assertRaises(b.OllamaDiagnosticFailure) as caught:
                b.ollama_inference(self.messages, self.load())
        metadata = caught.exception.diagnostic
        self.assertEqual(metadata["category"], "unfinished_or_tools")
        self.assertEqual(metadata["done_reason"], "length")
        self.assertFalse(metadata["content_present"])
        self.assertTrue(metadata["thinking_present"])
        self.assertEqual(metadata["response_bytes"], len(raw))
        self.assertNotIn(sensitive, json.dumps(metadata))
        self.assertNotIn("fixture prompt", json.dumps(metadata))

    def test_http_invalid_json_and_transport_fail_with_bounded_types(self):
        cases = [
            ((503, {}, b"SECRET_BODY"), "http_status", 503),
            ((200, {}, b'{"private":"SECRET_BODY",'), "invalid_json", 200),
        ]
        for fake, category, code in cases:
            with self.subTest(category=category), patch.object(b, "_post", return_value=fake):
                with self.assertRaises(b.OllamaDiagnosticFailure) as caught:
                    b.ollama_inference(self.messages, self.load())
            self.assertEqual(caught.exception.diagnostic["category"], category)
            self.assertEqual(caught.exception.diagnostic["http_status"], code)
            self.assertNotIn("SECRET_BODY", str(caught.exception.diagnostic))
        with patch.object(b, "_post", side_effect=b.BackendError("SECRET_TRANSPORT")):
            with self.assertRaises(b.OllamaDiagnosticFailure) as caught:
                b.ollama_inference(self.messages, self.load())
        self.assertEqual(caught.exception.diagnostic["category"], "transport")
        self.assertIsNone(caught.exception.diagnostic["http_status"])
        self.assertNotIn("SECRET_TRANSPORT", str(caught.exception))

    def test_bad_envelope_and_empty_text_are_distinct(self):
        cases = [((200, {}, b"[]"), "invalid_envelope"),
                 ((200, {}, self.fake_ollama({"message": {"role": "assistant", "content": ""}})), "invalid_text")]
        for value, category in cases:
            with self.subTest(category=category), patch.object(b, "_post", return_value=value):
                with self.assertRaises(b.OllamaDiagnosticFailure) as caught:
                    b.ollama_inference(self.messages, self.load())
                self.assertEqual(caught.exception.diagnostic["category"], category)

    def test_diagnostic_constructor_refuses_extra_field_or_arbitrary_string(self):
        safe = b._failure_metadata("transport", time.monotonic())
        for changes in ({"raw_response": "SECRET"}, {"category": "SECRET"},
                        {"elapsed_ms": "999"}, {"done_reason": "SECRET"}):
            with self.subTest(changes=changes), self.assertRaises(b.BackendError):
                b.OllamaDiagnosticFailure(dict(safe, **changes))

    def test_signed_502_reaches_authenticated_caller_without_content(self):
        cfg = self.load({"qwen35_08b_think_false": True})
        cfg["port"] = 0
        cfg["key"] = self.key
        sensitive = "PRIVATE_THINKING_NOT_FOR_DIAGNOSTIC"
        observed = []

        def injected(messages, inner_cfg):
            observed.append(messages)
            raw = self.fake_ollama({"done_reason": "length", "message": {
                "role": "assistant", "content": "", "thinking": sensitive}})
            # Local Ollama endpoint is mocked only inside the broker inference.
            with patch.object(b, "_post", return_value=(200, {}, raw)):
                return b.ollama_inference(messages, inner_cfg)

        server = b.Broker(cfg, inference=injected)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        worker.start()
        try:
            client = b.AuthenticatedBackend(port=server.server_address[1],
                key=self.key, model=cfg["model"], timeout_seconds=2)
            with self.assertRaises(RetryableModelError) as caught:
                client.respond(messages=self.messages, tools=[])
            report = str(caught.exception)
            self.assertIn("ollama_failure category=unfinished_or_tools", report)
            self.assertIn("done_reason=length", report)
            self.assertIn("thinking_present=True", report)
            self.assertNotIn(sensitive, report)
            self.assertNotIn("fixture prompt", report)
            self.assertEqual(len(observed), 1)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_unauthenticated_or_forged_502_cannot_install_diagnostic(self):
        client = b.AuthenticatedBackend(port=20000, key=self.key, model=self.cfg["model"])
        forged = b.canonical({"error": "bounded_inference_rejected", "diagnostic": {
            "schema": b.DIAGNOSTIC_SCHEMA, "category": "invalid_text", "elapsed_ms": 1,
            "http_status": 200, "done_reason": "stop", "content_present": False,
            "thinking_present": False, "response_bytes": 5}})
        with patch.object(b, "_post", return_value=(502, {"X-Initiative-MAC": "bad"}, forged)):
            with self.assertRaises(RetryableModelError) as caught:
                client.respond(messages=self.messages, tools=[])
        self.assertIn("broker_http_502", str(caught.exception))
        self.assertNotIn("ollama_failure", str(caught.exception))

        # Even possession of a valid test HMAC cannot smuggle raw model text
        # into a diagnostic that a consumer might log as a retryable error.
        malformed = json.loads(forged)
        malformed["diagnostic"]["raw_content"] = "PRIVATE_MODEL_OUTPUT"

        def signed_but_malformed(_port, _path, body, _headers, _timeout):
            nonce = json.loads(body)["nonce"]
            raw = b.canonical(malformed)
            signature = b._mac(self.key, b"RESPONSE\n" + nonce.encode() + b"\n", raw)
            return 502, {"X-Initiative-MAC": signature}, raw

        with patch.object(b, "_post", side_effect=signed_but_malformed):
            with self.assertRaises(RetryableModelError) as caught:
                client.respond(messages=self.messages, tools=[])
        self.assertIn("invalid_broker_diagnostic", str(caught.exception))
        self.assertNotIn("PRIVATE_MODEL_OUTPUT", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
