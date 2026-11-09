"""Resident-side IPC for a separately governed Windows STOP custodian.

This module does not install a service, authorize a recipient, or own a STOP
signing key.  It uses authenticated local named pipes and bounded JSON bytes;
the custodian must own final publication and durable revocation history.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
from multiprocessing.connection import Client
from pathlib import Path
import re

from .stop_authority import StopAuthorityUnavailable


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_MAX_FRAME = 16384
_MAX_BODY = 4096
_PIPE = r"\\.\pipe\VERA_Obsession_Stop_V1"


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _forbid_constant(value):
    raise ValueError("nonfinite JSON number")


def _wire_decode(body):
    if type(body) is not bytes or len(body) > _MAX_FRAME:
        raise ValueError("invalid custodian frame")
    value = json.loads(body.decode("utf-8", errors="strict"),
                       object_pairs_hook=_unique_pairs,
                       parse_constant=_forbid_constant)
    if type(value) is not dict:
        raise ValueError("custodian frame must be an object")
    return value


def _wire_send(conn, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(raw) > _MAX_FRAME:
        raise ValueError("oversized custodian request")
    conn.send_bytes(raw)
    response = _wire_decode(conn.recv_bytes(_MAX_FRAME))
    if set(response) == {"ok", "error"} and response["ok"] is False:
        raise StopAuthorityUnavailable("CUSTODIAN_DENIED:" + str(response["error"])[:120])
    if set(response) != {"ok", "result"} or response["ok"] is not True or type(response["result"]) is not dict:
        raise StopAuthorityUnavailable("MALFORMED_CUSTODIAN_RESPONSE")
    return response["result"]


def _finite_now(now):
    if type(now) not in (int, float) or not math.isfinite(now):
        raise StopAuthorityUnavailable("INVALID_CUSTODIAN_CLOCK")
    return float(now)


def _hex_digest(value, label):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise StopAuthorityUnavailable("INVALID_" + label)
    return value


class CustodianPipeClient:
    """Local IPC adapter; the resident principal never obtains the STOP key.

    A transport authkey merely authenticates the local IPC session.  It is
    *not* an owner STOP signing key or permission to reset host custody.
    """

    def __init__(self, *, authkey_file, output_root,
                 pipe_name=_PIPE, family="AF_PIPE", allow_test_unix=False):
        self._key_path = Path(authkey_file)
        self.output_root = Path(output_root).resolve()
        if family == "AF_PIPE":
            if pipe_name != _PIPE:
                raise ValueError("unexpected STOP pipe name")
        elif family == "AF_UNIX" and allow_test_unix:
            if type(pipe_name) is not str or not pipe_name:
                raise ValueError("invalid fixture socket")
        else:
            raise ValueError("unsupported STOP IPC transport")
        self._address = pipe_name
        self._family = family

    def _connect(self):
        try:
            if not self._key_path.is_file() or self._key_path.is_symlink():
                raise StopAuthorityUnavailable("CUSTODIAN_CLIENT_KEY_UNAVAILABLE")
            key = self._key_path.read_bytes()
            if not 32 <= len(key) <= 64:
                raise StopAuthorityUnavailable("CUSTODIAN_CLIENT_KEY_INVALID")
            # Windows pipe ACL and effective process identity must separately
            # be verified by the installer. File existence alone is not proof.
            return Client(self._address, family=self._family, authkey=key)
        except StopAuthorityUnavailable:
            raise
        except Exception as exc:
            raise StopAuthorityUnavailable("CUSTODIAN_CONNECT_FAILED") from exc

    def hold_active(self, *, generation, now):
        """Legacy client-side lease is intentionally prohibited in host v1."""
        raise StopAuthorityUnavailable("HOST_CUSTODIAN_HAS_NO_CLIENT_SIDE_LEASE")

    def revoke(self, *, generation, now):
        """Resident runtime cannot falsely claim an operator STOP receipt."""
        raise StopAuthorityUnavailable("OWNER_STOP_REQUIRES_SEPARATE_PROTECTED_OPERATOR")

    def publish_local(self, *, generation, artifact_id, source_digest,
                      payload, grant, grant_mac, now):
        """Ask host custodian to write *its* protected output atomically.

        A local approval or held lease does not authorize client-side os.link.
        The operator-signed grant must be minted outside the resident process.
        """
        when = _finite_now(now)
        if type(generation) is not str or not generation:
            raise StopAuthorityUnavailable("INVALID_STOP_GENERATION")
        artifact_id = _hex_digest(artifact_id, "ARTIFACT_ID")
        source_digest = _hex_digest(source_digest, "SOURCE_DIGEST")
        _hex_digest(grant_mac, "OPERATOR_GRANT_MAC")
        if type(payload) is not bytes or not 1 <= len(payload) <= _MAX_BODY:
            raise StopAuthorityUnavailable("INVALID_LOCAL_PUBLICATION_BODY")
        expected_grant = {"generation", "artifact_id", "source_digest", "scope", "expires_at"}
        if type(grant) is not dict or set(grant) != expected_grant:
            raise StopAuthorityUnavailable("INVALID_HOST_GRANT")
        if (grant["generation"] != generation
                or grant["artifact_id"] != artifact_id
                or grant["source_digest"] != source_digest
                or grant["scope"] != "LOCAL_SYNTHETIC_HANDOFF_ONLY"
                or type(grant["expires_at"]) not in (int, float)
                or not math.isfinite(grant["expires_at"])
                or grant["expires_at"] <= when):
            raise StopAuthorityUnavailable("HOST_GRANT_NOT_CURRENT")
        request = {
            "op": "PUBLISH", "generation": generation, "artifact_id": artifact_id,
            "source_digest": source_digest,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "grant": grant, "grant_mac": grant_mac, "now": when,
        }
        conn = self._connect()
        try:
            response = _wire_send(conn, request)
        except Exception as exc:
            raise StopAuthorityUnavailable("CUSTODIAN_PUBLICATION_UNVERIFIED") from exc
        finally:
            conn.close()
        if set(response) != {"state", "path", "sha256", "epoch", "generation"}:
            raise StopAuthorityUnavailable("INVALID_CUSTODIAN_RECEIPT")
        if (response["state"] not in ("PUBLISHED", "ALREADY_IDENTICAL")
                or response["generation"] != generation
                or type(response["epoch"]) is not int or response["epoch"] < 0
                or response["sha256"] != hashlib.sha256(payload).hexdigest()):
            raise StopAuthorityUnavailable("MISMATCHED_CUSTODIAN_RECEIPT")
        expected_path = (self.output_root / (artifact_id + ".json")).resolve()
        try:
            observed_path = Path(response["path"]).resolve()
        except Exception as exc:
            raise StopAuthorityUnavailable("INVALID_CUSTODIAN_ARTIFACT_PATH") from exc
        if observed_path != expected_path:
            raise StopAuthorityUnavailable("CUSTODIAN_OUTPUT_OUTSIDE_PINNED_ROOT")
        return response
