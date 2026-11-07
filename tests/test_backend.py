"""Real loopback contract tests; fake only the underlying model boundary."""
import http.client
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
from pre_active.engine import RetryableModelError, NonRetryableModelError


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = secrets.token_bytes(32)
        self.calls = 0
        self.cfg = {"schema": b.SCHEMA, "port": 0, "model": "synthetic-model",
            "key": self.key, "token_file": str(Path(self.tmp.name) / "key"),
            "broker_state": str(Path(self.tmp.name) / "broker.sqlite3"),
            "timeout_seconds": 2, "max_tokens": 32, "expires_at": time.time()+120,
            "max_calls": 3}
        self.broker = None
        self.start()

    def infer(self, messages, cfg):
        self.calls += 1
        return '{"message":"Synthetic diagnostic ready.","reason":"Configured timer."}'

    def start(self):
        self.broker = b.Broker(self.cfg, inference=self.infer)
        self.thread = threading.Thread(target=self.broker.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        self.port = self.broker.server_address[1]
        self.client = b.AuthenticatedBackend(port=self.port, key=self.key, model="synthetic-model", timeout_seconds=2)

    def stop(self):
        self.broker.shutdown()
        self.broker.server_close()
        self.thread.join(2)

    def tearDown(self):
        self.stop()
        self.tmp.cleanup()

    def request(self, *, body=None, signature=None, path="/v1/evaluate"):
        if body is None:
            body = b.canonical({"nonce": secrets.token_hex(16), "issued_at": time.time(),
                                "messages":[{"role":"user","content":"synthetic"}]})
        headers = {"Content-Type":"application/json", "X-Initiative-MAC": signature if signature is not None else b._mac(self.key,b"REQUEST\n",body)}
        return b._post(self.port,path,body,headers,2)

    def test_missing_or_wrong_auth_cannot_invoke_model(self):
        self.assertEqual(self.request(signature="wrong")[0],401)
        self.assertEqual(self.calls,0)

    def test_mutually_authenticated_real_http_exchange(self):
        reply = self.client.respond(messages=[{"role":"user","content":"synthetic"}], tools=[])
        self.assertIn("Synthetic diagnostic",reply.final_text)
        self.assertEqual(self.calls,1)

    def test_same_signed_nonce_rejected_after_broker_restart(self):
        body=b.canonical({"nonce":"a"*32,"issued_at":time.time(),"messages":[{"role":"user","content":"synthetic"}]})
        self.assertEqual(self.request(body=body)[0],200)
        self.stop(); self.start()
        self.assertEqual(self.request(body=body)[0],409)
        self.assertEqual(self.calls,1)

    def test_total_inference_budget_survives_restart(self):
        for _ in range(3):
            self.assertEqual(self.request()[0],200)
        self.stop(); self.start()
        self.assertEqual(self.request()[0],429)
        self.assertEqual(self.calls,3)

    def test_signed_expired_request_is_not_authority(self):
        body=b.canonical({"nonce":"b"*32,"issued_at":time.time()-120,"messages":[{"role":"user","content":"synthetic"}]})
        self.assertEqual(self.request(body=body)[0],410)
        self.assertEqual(self.calls,0)

    def test_only_fixed_path_and_method(self):
        self.assertEqual(self.request(path="/send")[0],404)
        c=http.client.HTTPConnection("127.0.0.1",self.port,timeout=2)
        c.request("GET","/v1/evaluate"); self.assertEqual(c.getresponse().status,405); c.close()
        self.assertEqual(self.calls,0)

    def test_model_tool_capability_is_rejected_before_transport(self):
        with self.assertRaises(NonRetryableModelError):
            self.client.respond(messages=[{"role":"user","content":"synthetic"}],tools=[{"name":"send"}])
        self.assertEqual(self.calls,0)

    def test_bad_response_signature_cannot_be_used(self):
        raw=b.canonical({"schema":b.SCHEMA,"model":"synthetic-model","text":"forged","done":True})
        with patch.object(b,"_post",return_value=(200,{"X-Initiative-MAC":"wrong"},raw)):
            with self.assertRaises(RetryableModelError):
                self.client.respond(messages=[{"role":"user","content":"synthetic"}],tools=[])

    def test_oversized_prompt_rejected_before_inference(self):
        with self.assertRaises(RetryableModelError):
            self.client.respond(messages=[{"role":"user","content":"x"*20000}],tools=[])
        self.assertEqual(self.calls,0)

    def test_ollama_truncation_wrong_model_and_tools_rejected(self):
        baseline={"model":"synthetic-model","done":True,"done_reason":"stop","message":{"role":"assistant","content":"{}"}}
        for changes in ({"done_reason":"length"},{"model":"other"},{"message":{"role":"assistant","content":"{}","tool_calls":[{}]}}):
            value=dict(baseline); value.update(changes)
            with self.subTest(changes=changes), patch.object(b,"_post",return_value=(200,{},b.canonical(value))):
                with self.assertRaises(b.BackendError):
                    b.ollama_inference([{"role":"user","content":"synthetic"}],self.cfg)

    def test_config_change_cannot_reset_durable_budget(self):
        self.stop()
        changed=dict(self.cfg,max_calls=4)
        with self.assertRaises(ValueError):
            b.Broker(changed,inference=self.infer)
        self.start()

    def test_broker_expiry_during_inference_discards_reply(self):
        self.broker.cfg["expires_at"]=time.time()+.02
        original=self.broker.inference
        def delayed(*args):
            time.sleep(.04)
            return original(*args)
        self.broker.inference=delayed
        self.assertEqual(self.request()[0],410)


if __name__ == "__main__":
    unittest.main()
