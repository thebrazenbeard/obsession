"""Obsession STOP custodian source candidate: local-only protected publisher.

This is deliberately NOT an installed Windows service or an authorized sender.
The installer must independently prove LocalSystem custody, executable integrity,
protected parent/root/target ACLs, trusted Python, and exactly one live server.

Transport: authenticated local multiprocessing.connection AF_PIPE (Windows),
AF_UNIX (test platforms), byte JSON only. Never use pickle recv()/send().
The resident transport key cannot sign operator REGISTER/GRANT/REVOKE commands.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
from multiprocessing.connection import Client, Listener
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import threading
import time


MAX_FRAME = 16384
MAX_PAYLOAD = 4096
ZERO_HASH = "0" * 64
ID = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
NONCE = re.compile(r"[a-f0-9]{32}\Z")


class CustodyDenied(PermissionError):
    pass


def canonical(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def exact_json(data: bytes) -> dict:
    if type(data) is not bytes or len(data) > MAX_FRAME:
        raise CustodyDenied("INVALID_FRAME")
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise CustodyDenied("DUPLICATE_JSON_KEY")
            d[k] = v
        return d
    try:
        out = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=unique,
                         parse_constant=lambda v: (_ for _ in ()).throw(ValueError("nonfinite")))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CustodyDenied("INVALID_JSON") from exc
    if type(out) is not dict:
        raise CustodyDenied("OBJECT_REQUIRED")
    return out


def valid_id(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise CustodyDenied("INVALID_GENERATION")
    return value


def valid_hex(value, name="INVALID_HASH"):
    if type(value) is not str or not HEX.fullmatch(value):
        raise CustodyDenied(name)
    return value


def valid_number(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise CustodyDenied("INVALID_TIME")
    return float(value)


def hmac_hex(key: bytes, data: object) -> str:
    return hmac.new(key, canonical(data), hashlib.sha256).hexdigest()


def grant_mac_hex(key: bytes, grant: dict) -> str:
    return hmac.new(key, b"OBSESSION_LOCAL_PUBLISH_GRANT_V1\x00" + canonical(grant), hashlib.sha256).hexdigest()


def _assert_protected_path(root: Path):
    """Basic source checks only; effective Windows ACLs MUST be verified externally."""
    if not root.is_dir() or root.is_symlink():
        raise CustodyDenied("PROTECTED_ROOT_MISSING_OR_LINK")
    for name in ("outbox", "private"):
        child = root / name
        if not child.is_dir() or child.is_symlink():
            raise CustodyDenied("PROTECTED_CHILD_MISSING_OR_LINK")
    journal = root / "private" / "stop-journal.jsonl"
    if not journal.is_file() or journal.is_symlink():
        raise CustodyDenied("JOURNAL_MISSING_OR_LINK")
    return journal


class Custodian:
    """One process, one lock, one protected append-only stop history.

    An attacker who can replace this protected journal OR the service executable
    is outside the source-only threat model. A full protected-journal rollback
    requires an additional independently anchored counter/TPM to detect.
    """
    def __init__(self, root: str | Path, operator_key: bytes, *, clock=time.time):
        self.root = Path(root).resolve()
        self.journal = _assert_protected_path(self.root)
        if type(operator_key) is not bytes or len(operator_key) < 32:
            raise CustodyDenied("OPERATOR_KEY_INVALID")
        self.operator_key = operator_key
        self.clock = clock
        self.lock = threading.RLock()
        self.epoch = -1
        self.prev = ZERO_HASH
        self.generations: dict[str, bool] = {}
        self.operator_nonces = set()
        self._load_journal()

    @staticmethod
    def initialize(root: str | Path):
        """One-shot setup ONLY after external host-owned root/ACL qualification."""
        root = Path(root).resolve()
        if not root.is_dir() or root.is_symlink():
            raise CustodyDenied("PRECREATED_PROTECTED_ROOT_REQUIRED")
        private = root / "private"
        outbox = root / "outbox"
        for child in (private, outbox):
            if child.exists():
                if not child.is_dir() or child.is_symlink():
                    raise CustodyDenied("PROTECTED_CHILD_UNSAFE")
            else:
                child.mkdir(mode=0o700)
        journal = private / "stop-journal.jsonl"
        if journal.exists():
            raise CustodyDenied("REFUSE_EXISTING_JOURNAL_RESET")
        base = {"seq": 0, "op": "GENESIS", "generation": "GENESIS__", "nonce": "-", "prev": ZERO_HASH}
        entry = dict(base, hash=hashlib.sha256(canonical(base)).hexdigest())
        fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(canonical(entry) + b"\n")
            f.flush()
            os.fsync(f.fileno())

    def _load_journal(self):
        with self.journal.open("rb") as f:
            rows = f.readlines()
        if not rows or any(not row.endswith(b"\n") for row in rows):
            raise CustodyDenied("JOURNAL_TRUNCATED")
        for expected, row in enumerate(rows):
            obj = exact_json(row.rstrip(b"\n"))
            if set(obj) != {"seq", "op", "generation", "nonce", "prev", "hash"}:
                raise CustodyDenied("JOURNAL_SCHEMA_CHANGED")
            base = {k: obj[k] for k in obj if k != "hash"}
            calc = hashlib.sha256(canonical(base)).hexdigest()
            if (type(obj["seq"]) is not int or obj["seq"] != expected
                    or obj["prev"] != self.prev or obj["hash"] != calc):
                raise CustodyDenied("JOURNAL_CHAIN_INVALID")
            op, generation, nonce = obj["op"], obj["generation"], obj["nonce"]
            if expected == 0:
                if op != "GENESIS" or generation != "GENESIS__" or nonce != "-":
                    raise CustodyDenied("GENESIS_INVALID")
            else:
                valid_id(generation)
                if type(nonce) is not str or not NONCE.fullmatch(nonce) or nonce in self.operator_nonces:
                    raise CustodyDenied("JOURNAL_NONCE_REPLAY")
                if op == "REGISTER" and generation not in self.generations:
                    self.generations[generation] = True
                elif op == "REVOKE" and self.generations.get(generation) is True:
                    self.generations[generation] = False
                elif op == "GRANT" and self.generations.get(generation) is True:
                    # Persist consumed operator nonce even for a grant that
                    # does not change registration state. Prevent its reuse
                    # after a service crash or restart.
                    pass
                else:
                    raise CustodyDenied("JOURNAL_INVALID_TRANSITION")
                self.operator_nonces.add(nonce)
            self.epoch = expected
            self.prev = obj["hash"]

    def _append(self, op: str, generation: str, nonce: str):
        base = {"seq": self.epoch + 1, "op": op, "generation": generation,
                "nonce": nonce, "prev": self.prev}
        entry = dict(base, hash=hashlib.sha256(canonical(base)).hexdigest())
        # Require one trusted server process and installer-enforced exclusion.
        with self.journal.open("ab", buffering=0) as f:
            f.write(canonical(entry) + b"\n")
            os.fsync(f.fileno())
        self.epoch += 1
        self.prev = entry["hash"]
        self.operator_nonces.add(nonce)

    def _operator(self, request: dict, required: set[str]):
        if set(request) != required:
            raise CustodyDenied("OPERATOR_REQUEST_SCHEMA")
        nonce = request.get("nonce")
        if type(nonce) is not str or not NONCE.fullmatch(nonce) or nonce in self.operator_nonces:
            raise CustodyDenied("OPERATOR_NONCE_REPLAY")
        mac = request.get("mac")
        valid_hex(mac, "OPERATOR_MAC_INVALID")
        signed = {k: v for k, v in request.items() if k != "mac"}
        if not hmac.compare_digest(mac, hmac_hex(self.operator_key, signed)):
            raise CustodyDenied("OPERATOR_PROOF_INVALID")
        return nonce

    def register(self, request: dict):
        with self.lock:
            nonce = self._operator(request, {"op", "generation", "nonce", "mac"})
            generation = valid_id(request["generation"])
            if request["op"] != "REGISTER" or generation in self.generations:
                raise CustodyDenied("GENERATION_NOT_FRESH")
            self._append("REGISTER", generation, nonce)
            self.generations[generation] = True
            return {"state": "REGISTERED", "generation": generation, "epoch": self.epoch}

    def revoke(self, request: dict):
        with self.lock:
            nonce = self._operator(request, {"op", "generation", "nonce", "mac"})
            generation = valid_id(request["generation"])
            if request["op"] != "REVOKE" or generation not in self.generations:
                raise CustodyDenied("UNKNOWN_GENERATION")
            if not self.generations[generation]:
                return {"state": "ALREADY_REVOKED", "generation": generation, "epoch": self.epoch}
            self._append("REVOKE", generation, nonce)
            self.generations[generation] = False
            return {"state": "REVOKED", "generation": generation, "epoch": self.epoch}

    def grant(self, request: dict):
        with self.lock:
            nonce = self._operator(request, {"op", "generation", "artifact_id", "source_digest", "expires_at", "nonce", "mac"})
            if request["op"] != "GRANT":
                raise CustodyDenied("UNKNOWN_OPERATOR_ACTION")
            g = valid_id(request["generation"])
            artifact = valid_hex(request["artifact_id"], "ARTIFACT_INVALID")
            digest = valid_hex(request["source_digest"])
            expiry = valid_number(request["expires_at"])
            now = valid_number(self.clock())
            if not self.generations.get(g) or not now < expiry <= now + 3600:
                raise CustodyDenied("GRANT_DENIED")
            grant = {"generation": g, "artifact_id": artifact, "source_digest": digest,
                     "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "expires_at": expiry}
            self._append("GRANT", g, nonce)
            return {"grant": grant, "grant_mac": grant_mac_hex(self.operator_key, grant), "epoch": self.epoch}

    @staticmethod
    def _validate_payload(payload: bytes, generation: str):
        if not 1 <= len(payload) <= MAX_PAYLOAD:
            raise CustodyDenied("PAYLOAD_SIZE_INVALID")
        obj = exact_json(payload)
        if (set(obj) != {"schema", "scope", "proposal_digest", "proposal", "contact_authorized", "delivery_verified"}
                or obj["schema"] != "initiative.local-handoff.v1"
                or obj["scope"] != "LOCAL_SYNTHETIC_HANDOFF_ONLY"
                or obj["contact_authorized"] is not False
                or obj["delivery_verified"] is not False
                or type(obj["proposal"]) is not dict):
            raise CustodyDenied("NOT_SYNTHETIC_LOCAL_PAYLOAD")
        p = obj["proposal"]
        if (p.get("generation") != generation or p.get("target_class") != "SYNTHETIC_LOCAL_ONLY"
                or p.get("contact_authorized") is not False
                or p.get("delivery_verified") is not False
                or p.get("execution_authorized") is not False):
            raise CustodyDenied("PROPOSAL_NOT_LOCAL_ONLY")

    def publish(self, request: dict):
        with self.lock:
            if set(request) != {"op", "generation", "artifact_id", "source_digest", "payload_b64", "now", "grant", "grant_mac"} or request["op"] != "PUBLISH":
                raise CustodyDenied("PUBLISH_SCHEMA")
            g = valid_id(request["generation"])
            artifact = valid_hex(request["artifact_id"], "ARTIFACT_INVALID")
            source_digest = valid_hex(request["source_digest"])
            valid_number(request["now"])
            if self.generations.get(g) is not True:
                raise CustodyDenied("STOP_OR_NOT_REGISTERED")
            grant, mac = request["grant"], request["grant_mac"]
            if type(grant) is not dict or set(grant) != {"generation", "artifact_id", "source_digest", "scope", "expires_at"}:
                raise CustodyDenied("GRANT_SCHEMA")
            if (grant["generation"] != g or grant["artifact_id"] != artifact
                    or grant["source_digest"] != source_digest
                    or grant["scope"] != "LOCAL_SYNTHETIC_HANDOFF_ONLY"
                    or not hmac.compare_digest(valid_hex(mac, "GRANT_MAC_INVALID"), grant_mac_hex(self.operator_key, grant))):
                raise CustodyDenied("GRANT_PROOF_INVALID")
            if not valid_number(self.clock()) < valid_number(grant["expires_at"]):
                raise CustodyDenied("GRANT_EXPIRED")
            p64 = request["payload_b64"]
            if type(p64) is not str or len(p64) > 4 * ((MAX_PAYLOAD + 2) // 3):
                raise CustodyDenied("PAYLOAD_B64_TOO_LARGE")
            try:
                payload = base64.b64decode(p64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise CustodyDenied("PAYLOAD_B64_INVALID") from exc
            if hashlib.sha256(payload).hexdigest() != source_digest:
                raise CustodyDenied("PAYLOAD_DIGEST_MISMATCH")
            self._validate_payload(payload, g)
            out_dir = self.root / "outbox"
            target = out_dir / (artifact + ".json")
            if target.is_symlink() or out_dir.is_symlink():
                raise CustodyDenied("OUTPUT_REPARSE_POINT")
            if target.exists():
                if target.read_bytes() != payload:
                    raise CustodyDenied("DIVERGENT_EXISTING_ARTIFACT")
                state = "ALREADY_IDENTICAL"
            else:
                fd, temp = tempfile.mkstemp(prefix=".pending-", dir=out_dir)
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(payload)
                        f.flush()
                        os.fsync(f.fileno())
                    if os.name == "nt":
                        os.rename(temp, target)
                    else:
                        os.link(temp, target)
                    state = "PUBLISHED"
                finally:
                    if os.path.exists(temp):
                        os.unlink(temp)
            return {"state": state, "generation": g, "epoch": self.epoch,
                    "path": str(target), "sha256": source_digest}

    def handle(self, request: dict):
        op = request.get("op")
        if op == "REGISTER":
            return self.register(request)
        if op == "REVOKE":
            return self.revoke(request)
        if op == "GRANT":
            return self.grant(request)
        if op == "PUBLISH":
            return self.publish(request)
        raise CustodyDenied("UNKNOWN_OPERATION")


def serve(*, root: str, address: str, transport_key: bytes, operator_key: bytes, family: str):
    state = Custodian(root, operator_key)
    listener = Listener(address=address, family=family, authkey=transport_key)
    slots = threading.BoundedSemaphore(32)
    def worker(conn):
        try:
            # One request per connection; no deserialization of pickle objects.
            if not conn.poll(5.0):
                return  # Silent peer cannot hold the service worker forever.
            request = exact_json(conn.recv_bytes(MAX_FRAME))
            try:
                result = {"ok": True, "result": state.handle(request)}
            except (CustodyDenied, ValueError, OSError) as exc:
                result = {"ok": False, "error": type(exc).__name__ + ":" + str(exc)[:120]}
            conn.send_bytes(canonical(result))
        except (OSError, EOFError):
            pass
        finally:
            conn.close()
            slots.release()
    try:
        while True:
            conn = listener.accept()
            if not slots.acquire(blocking=False):
                conn.close()
                continue
            threading.Thread(target=worker, args=(conn,), daemon=True).start()
    finally:
        listener.close()


def request(address: str, family: str, transport_key: bytes, body: dict):
    data = canonical(body)
    if len(data) > MAX_FRAME:
        raise CustodyDenied("CLIENT_REQUEST_TOO_LARGE")
    conn = Client(address, family=family, authkey=transport_key)
    try:
        conn.send_bytes(data)
        if not conn.poll(5.0):
            raise CustodyDenied("CUSTODIAN_RESPONSE_TIMEOUT")
        response = exact_json(conn.recv_bytes(MAX_FRAME))
        if set(response) == {"ok", "result"} and response["ok"] is True:
            return response["result"]
        if set(response) == {"ok", "error"} and response["ok"] is False:
            raise CustodyDenied(str(response["error"]))
        raise CustodyDenied("MALFORMED_RESPONSE")
    finally:
        conn.close()


def make_operator_request(key: bytes, op: str, **fields):
    body = {"op": op, "nonce": secrets.token_hex(16), **fields}
    return dict(body, mac=hmac_hex(key, body))


def _config(path: Path):
    obj = exact_json(path.read_bytes())
    if set(obj) != {"root", "address", "family", "transport_key_hex", "operator_key_hex"}:
        raise CustodyDenied("CONFIG_SCHEMA_INVALID")
    if obj["family"] not in {"AF_PIPE", "AF_UNIX"}:
        raise CustodyDenied("CONFIG_FAMILY_INVALID")
    transport = bytes.fromhex(valid_hex(obj["transport_key_hex"], "TRANSPORT_KEY_INVALID"))
    operator = bytes.fromhex(valid_hex(obj["operator_key_hex"], "OPERATOR_KEY_INVALID"))
    if transport == operator:
        raise CustodyDenied("AUTH_ROLES_NOT_SEPARATE")
    return obj, transport, operator


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("serve", help="Run custodian (requires separate OS service supervisor)")
    p.add_argument("--config", required=True)
    p = sub.add_parser("initialize", help="One-shot protected journal bootstrap")
    p.add_argument("--root", required=True)
    args = parser.parse_args(argv)
    if args.action == "initialize":
        Custodian.initialize(args.root)
        return 0
    cfg, transport, operator = _config(Path(args.config))
    if os.name == "nt" and cfg["family"] != "AF_PIPE":
        raise CustodyDenied("WINDOWS_AF_PIPE_REQUIRED")
    serve(root=cfg["root"], address=cfg["address"], family=cfg["family"],
          transport_key=transport, operator_key=operator)
    return 0


if __name__ == "__main__":
    sys.exit(main())
