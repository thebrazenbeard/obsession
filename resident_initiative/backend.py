"""Mutually authenticated, finite loopback inference broker; no effect API.

The broker authenticates its caller and responses with a private HMAC key.
The fixed underlying Ollama process remains host-trusted and unattested.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import secrets
import socket
import sqlite3
import sys
import threading
import time


MAX_REQUEST = 18000
MAX_RESPONSE = 32768
SCHEMA = "INITIATIVE_BACKEND_V1"


class BackendError(RuntimeError):
    """A bounded inference failure, never an authorization disposition."""


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite JSON constant")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _number(value, low, high):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError("invalid backend numeric bound")
    return value


def _mac(key, domain, raw):
    return hmac.new(key, domain + raw, hashlib.sha256).hexdigest()


def _read_key(path):
    p = Path(path)
    if not p.is_absolute() or p.stat().st_size > 128:
        raise ValueError("private key file must be a small absolute file")
    value = p.read_text(encoding="ascii").strip()
    if len(value) != 64:
        raise ValueError("private key must contain 32 random bytes in hex")
    return bytes.fromhex(value)


def load_config(path):
    p = Path(path)
    if p.stat().st_size > 4096:
        raise ValueError("backend config too large")
    cfg = strict_json(p.read_text(encoding="utf-8-sig"))
    required = {"schema", "port", "model", "token_file", "timeout_seconds", "max_tokens",
                "broker_state", "expires_at", "max_calls"}
    if type(cfg) is not dict or set(cfg) != required or cfg["schema"] != SCHEMA:
        raise ValueError("invalid backend config schema")
    if type(cfg["port"]) is not int or not 1024 <= cfg["port"] <= 65535 or cfg["port"] == 11434:
        raise ValueError("invalid broker port")
    if type(cfg["model"]) is not str or not 1 <= len(cfg["model"]) <= 100 or any(ord(c) < 33 for c in cfg["model"]):
        raise ValueError("invalid model name")
    _number(cfg["timeout_seconds"], 1, 60)
    if type(cfg["max_tokens"]) is not int or not 16 <= cfg["max_tokens"] <= 384:
        raise ValueError("invalid generation budget")
    _number(cfg["expires_at"], 1, 10**11)
    if cfg["expires_at"] > time.time() + 3600:
        raise ValueError("broker config lifetime exceeds one hour")
    if type(cfg["max_calls"]) is not int or not 1 <= cfg["max_calls"] <= 16:
        raise ValueError("invalid total inference budget")
    if not Path(cfg["broker_state"]).is_absolute():
        raise ValueError("broker state requires absolute private path")
    cfg["key"] = _read_key(cfg["token_file"])
    return cfg


def _post(port, path, body, headers, timeout):
    """No proxy/redirect support; hard wall deadline closes the actual socket."""
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError as exc:
        raise BackendError("bounded_connect_failure") from exc
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.sock = sock
    def abort():
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
    deadline = threading.Timer(timeout, abort)
    deadline.daemon = True
    deadline.start()
    try:
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise BackendError("response_byte_budget")
        return response.status, dict(response.getheaders()), raw
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        raise BackendError("bounded_transport_failure") from exc
    finally:
        deadline.cancel()
        conn.close()


def _messages(value):
    if type(value) is not list or not 1 <= len(value) <= 16:
        raise BackendError("invalid_messages")
    for item in value:
        if type(item) is not dict or set(item) != {"role", "content"}:
            raise BackendError("invalid_message_fields")
        if item["role"] not in ("system", "user", "assistant") or type(item["content"]) is not str:
            raise BackendError("invalid_message_type")
    if len(canonical(value)) > 14000:
        raise BackendError("prompt_byte_budget")
    return value


class AuthenticatedBackend:
    evidence_class = "AUTHENTICATED_LOCAL_BROKER_REPLY_UNATTESTED"
    def __init__(self, *, port, key, model, timeout_seconds=60, max_tokens=256):
        self.port, self.key, self.model = port, key, model
        self.timeout = timeout_seconds
        self.max_tokens = max_tokens

    def respond(self, *, messages, tools):
        from pre_active.engine import ModelResponse, RetryableModelError, NonRetryableModelError
        if tools:
            raise NonRetryableModelError("initiative backend forbids tools")
        try:
            body = canonical({"nonce": secrets.token_hex(16), "issued_at": time.time(),
                              "messages": _messages(messages)})
            payload = strict_json(body)
            status, headers, raw = _post(self.port, "/v1/evaluate", body,
                {"Content-Type": "application/json", "X-Initiative-MAC": _mac(self.key, b"REQUEST\n", body)}, self.timeout)
            if status != 200:
                raise BackendError("broker_http_" + str(status))
            signature = next((v for k, v in headers.items() if k.lower() == "x-initiative-mac"), "")
            expected = _mac(self.key, b"RESPONSE\n" + payload["nonce"].encode() + b"\n", raw)
            if not hmac.compare_digest(signature, expected):
                raise BackendError("broker_response_authentication_failed")
            result = strict_json(raw)
            if type(result) is not dict or set(result) != {"schema", "model", "text", "done"} or result["schema"] != SCHEMA or result["model"] != self.model or result["done"] is not True:
                raise BackendError("invalid_broker_reply")
            if type(result["text"]) is not str or not result["text"].strip() or len(result["text"].encode()) > 4096:
                raise BackendError("invalid_broker_text")
            return ModelResponse(final_text=result["text"])
        except (BackendError, ValueError, TypeError, KeyError) as exc:
            # Only finite inference retries; no effect is attempted by this backend.
            raise RetryableModelError("initiative inference rejected: " + str(exc), category="initiative_backend") from exc


def backend_from_config(path):
    cfg = load_config(path)
    if time.time() >= cfg["expires_at"]:
        raise ValueError("backend config expired")
    return AuthenticatedBackend(port=cfg["port"], key=cfg["key"], model=cfg["model"],
        timeout_seconds=cfg["timeout_seconds"], max_tokens=cfg["max_tokens"])


def ollama_inference(messages, cfg):
    body = canonical({"model": cfg["model"], "messages": messages, "stream": False,
        "format": "json", "keep_alive": "2m", "options": {"num_predict": cfg["max_tokens"],
        "num_ctx": 4096, "temperature": 0, "seed": 20261106}})
    status, _, raw = _post(11434, "/api/chat", body, {"Content-Type": "application/json"}, cfg["timeout_seconds"])
    if status != 200:
        raise BackendError("local_model_http_" + str(status))
    value = strict_json(raw)
    if type(value) is not dict or type(value.get("message")) is not dict:
        raise BackendError("invalid_local_model_envelope")
    msg = value.get("message", {})
    if value.get("model") != cfg["model"] or value.get("done") is not True or value.get("done_reason") != "stop" or msg.get("role") != "assistant" or msg.get("tool_calls"):
        raise BackendError("local_model_not_completed_or_tools")
    text = msg.get("content")
    if type(text) is not str or not text.strip() or len(text.encode()) > 4096:
        raise BackendError("invalid_local_model_text")
    return text


class Broker(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, cfg, *, inference=ollama_inference):
        self.cfg, self.inference = cfg, inference
        self.inference_lock = threading.Lock()
        self.handler_slots = threading.BoundedSemaphore(4)
        self.identity = hashlib.sha256(canonical({k: v for k, v in cfg.items() if k != "key"})).hexdigest()
        with closing(sqlite3.connect(cfg["broker_state"])) as db, db:
            db.executescript("CREATE TABLE IF NOT EXISTS config (identity TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS admissions (nonce TEXT PRIMARY KEY, at REAL NOT NULL);")
            old = db.execute("SELECT identity FROM config").fetchone()
            if old and old[0] != self.identity:
                raise ValueError("broker state configuration conflict")
            db.execute("INSERT OR IGNORE INTO config VALUES (?)", (self.identity,))
        super().__init__(("127.0.0.1", cfg["port"]), BrokerHandler)

    def process_request(self, request, client_address):
        if not self.handler_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.handler_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.handler_slots.release()

    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (OSError, TimeoutError)):
            print("broker_handler_failure", file=sys.stderr)

    def admit(self, nonce):
        with closing(sqlite3.connect(self.cfg["broker_state"], timeout=5)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM admissions WHERE nonce=?", (nonce,)).fetchone():
                return 409
            if db.execute("SELECT count(*) FROM admissions").fetchone()[0] >= self.cfg["max_calls"]:
                return 429
            db.execute("INSERT INTO admissions VALUES (?,?)", (nonce, time.time()))
        return 200


class BrokerHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never record model prompts, authentication material or text.

    def setup(self):
        super().setup()
        self.connection.settimeout(3)
        def close_admission():
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
        self._close_admission = close_admission
        self._deadline = threading.Timer(3, close_admission)
        self._deadline.daemon = True
        self._deadline.start()

    def finish(self):
        self._deadline.cancel()
        super().finish()

    def _reply(self, code, payload, nonce=None):
        raw = canonical(payload)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        if nonce:
            self.send_header("X-Initiative-MAC", _mac(self.server.cfg["key"], b"RESPONSE\n" + nonce.encode() + b"\n", raw))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except OSError:
            pass

    def do_GET(self):
        self._reply(405, {"error": "method_rejected"})

    def do_POST(self):
        cfg = self.server.cfg
        if self.path != "/v1/evaluate":
            return self._reply(404, {"error": "path_rejected"})
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding") or not 1 <= int(lengths[0]) <= MAX_REQUEST:
                return self._reply(413, {"error": "request_budget"})
            raw = self.rfile.read(int(lengths[0]))
            expected = _mac(cfg["key"], b"REQUEST\n", raw)
            signatures = self.headers.get_all("X-Initiative-MAC", [])
            if len(signatures) != 1 or not hmac.compare_digest(signatures[0], expected):
                return self._reply(401, {"error": "unauthorized"})
            value = strict_json(raw)
            if type(value) is not dict or set(value) != {"nonce", "issued_at", "messages"}:
                raise BackendError("invalid_request")
            nonce = value["nonce"]
            if type(nonce) is not str or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
                raise BackendError("invalid_nonce")
            issued = _number(value["issued_at"], 1, 10**11)
            if abs(time.time() - issued) > 60 or time.time() >= cfg["expires_at"]:
                return self._reply(410, {"error": "expired"})
            messages = _messages(value["messages"])
            if not self.server.inference_lock.acquire(blocking=False):
                return self._reply(429, {"error": "inference_busy"})
            try:
                self._deadline.cancel()
                self._deadline = threading.Timer(cfg["timeout_seconds"] + 1, self._close_admission)
                self._deadline.daemon = True
                self._deadline.start()
                admitted = self.server.admit(nonce)
                if admitted != 200:
                    return self._reply(admitted, {"error": "replay_or_budget"})
                text = self.server.inference(messages, cfg)
                if time.time() >= cfg["expires_at"]:
                    return self._reply(410, {"error": "expired_during_inference"})
                return self._reply(200, {"schema": SCHEMA, "model": cfg["model"], "text": text, "done": True}, nonce)
            finally:
                self.server.inference_lock.release()
        except (OSError, ValueError, TypeError, KeyError, BackendError):
            return self._reply(502, {"error": "bounded_inference_rejected"})


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["broker"])
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    with Broker(cfg) as broker:
        broker.timeout = .5
        while time.time() < cfg["expires_at"]:
            broker.handle_request()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
