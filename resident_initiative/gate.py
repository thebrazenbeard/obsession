"""Owner-controlled local output gate, separate from model proposal creation.

No recipient, network delivery, phone credentials or device API exists here.
An explicit persisted owner grant binds one proposal digest and local directory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid

from .runtime import CommitDenial, Runtime, canonical, digest, finite
from .deps import PROVENANCE
from pre_active.engine import ModelResponse


class LocalHandoffGate:
    def __init__(self, runtime):
        self.runtime = runtime

    def _verified_proposal(self, row, now):
        """Readback actual bytes; a stored digest claim is not verification."""
        try:
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate proposal key")
                    value[key] = item
                return value
            body = json.loads(row["body_json"], object_pairs_hook=unique)
            required = {"schema", "proposal_id", "idempotency_key", "event_id", "generation",
                        "goal_digest", "created_at", "expires_at", "target_class", "message",
                        "reason", "salience", "execution_authorized", "contact_authorized",
                        "delivery_verified", "provider_evidence", "provenance",
                        "origin", "category", "propose_only", "ttl_seconds", "evidence_class"}
            if (type(body) is not dict or set(body) != required
                    or digest(body) != row["proposal_digest"]
                    or body["schema"] != "initiative.proposal.v1"
                    or body["origin"] != "OBSESSION_RESIDENT_SYNTHETIC_V1"
                    or body["category"] != "OWNER_DIRECTED_SYNTHETIC_DIAGNOSTIC"
                    or body["propose_only"] is not True
                    or body["proposal_id"] != row["proposal_id"]
                    or body["idempotency_key"] != row["proposal_id"]
                    or body["event_id"] != row["event_id"]
                    or body["generation"] != self.runtime.generation
                    or body["goal_digest"] != self.runtime.config_digest
                    or body["target_class"] != "SYNTHETIC_LOCAL_ONLY"
                    or body["expires_at"] != self.runtime.config.expires_at
                    or not 0 < finite(body["ttl_seconds"], "proposal TTL") <= 86400
                    or body["ttl_seconds"] != body["expires_at"] - finite(body["created_at"], "proposal created time")
                    or type(body["evidence_class"]) is not str
                    or body["evidence_class"] != body["provider_evidence"]
                    or body["provenance"] != PROVENANCE
                    or any(body[field] is not False for field in ("execution_authorized", "contact_authorized", "delivery_verified"))):
                raise ValueError("proposal binding changed")
            Runtime.validate_output(ModelResponse(final_text=canonical({"message": body["message"], "reason": body["reason"]})))
            return body
        except (KeyError, TypeError, ValueError) as exc:
            self.runtime._record(row["proposal_id"], "REJECTED_LOCAL_HANDOFF",
                                 {"reason": "PROPOSAL_INTEGRITY_FAILURE"}, now)
            raise CommitDenial("stored proposal failed fresh integrity verification") from exc

    def authorize(self, proposal_id, directory, *, expires_at, now=None):
        """Explicit owner CLI/API action. It grants only local file export."""
        now = self.runtime.clock() if now is None else now
        directory = str(Path(directory).resolve())
        with self.runtime.transaction():
            reason = self.runtime._hold_reason(self.runtime._owner(), now)
            if reason:
                raise CommitDenial(reason)
            row = self.runtime.store.connection.execute("SELECT * FROM initiative_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
            if row is None:
                raise KeyError("proposal does not exist")
            self._verified_proposal(row, now)
            if not now < finite(expires_at, "grant expiry") <= min(self.runtime.config.expires_at, now + 3600):
                raise ValueError("local grant expiry must be fresh and bounded")
            grant_id = str(uuid.uuid4())
            self.runtime.store.connection.execute("INSERT INTO initiative_local_grants VALUES(?,?,?,?,?,?,NULL,NULL)",
                                          (grant_id, proposal_id, row["proposal_digest"], self.runtime.generation, directory, expires_at))
        return {"schema": "initiative.local-grant.v1", "grant_id": grant_id,
                "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "proposal_id": proposal_id,
                "proposal_digest": row["proposal_digest"], "generation": self.runtime.generation,
                "directory": directory, "expires_at": expires_at, "contact_authorized": False}

    def export(self, proposal_id, grant_path, directory, *, now=None):
        now = self.runtime.clock() if now is None else now
        grant_file = json.loads(Path(grant_path).read_text(encoding="utf-8"))
        if type(grant_file) is not dict or grant_file.get("scope") != "LOCAL_SYNTHETIC_HANDOFF_ONLY":
            raise PermissionError("explicit local synthetic grant required")
        target_directory = Path(directory).resolve()
        with self.runtime.transaction():
            reason = self.runtime._hold_reason(self.runtime._owner(), now)
            if reason:
                raise CommitDenial(reason)
            grant = self.runtime.store.connection.execute("SELECT * FROM initiative_local_grants WHERE grant_id=?", (grant_file.get("grant_id"),)).fetchone()
            row = self.runtime.store.connection.execute("SELECT * FROM initiative_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
            if row is not None:
                proposal = self._verified_proposal(row, now)
            if (grant is None or row is None or grant["proposal_id"] != proposal_id
                    or grant["generation"] != self.runtime.generation or grant["proposal_digest"] != row["proposal_digest"]
                    or grant["directory"] != str(target_directory) or grant["expires_at"] <= now
                    or grant_file.get("proposal_digest") != row["proposal_digest"]):
                self.runtime._record(proposal_id, "REJECTED_LOCAL_HANDOFF", {"reason": "MISSING_OR_INVALID_HOST_GRANT"}, now)
                raise CommitDenial("local handoff grant is invalid")
            target_directory.mkdir(parents=True, exist_ok=True)
            target = target_directory / (proposal_id.removeprefix("sha256:") + ".json")
            payload = (canonical({"schema": "initiative.local-handoff.v1", "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY",
                                  "proposal_digest": row["proposal_digest"], "proposal": proposal,
                                  "delivery_verified": False, "contact_authorized": False}) + "\n").encode("utf-8")
            if target.exists():
                if target.read_bytes() != payload:
                    raise RuntimeError("divergent local handoff artifact; no overwrite")
            else:
                handle, temporary = tempfile.mkstemp(prefix=".initiative-", dir=target_directory)
                try:
                    with os.fdopen(handle, "wb") as output:
                        output.write(payload)
                        output.flush()
                        os.fsync(output.fileno())
                    # Atomic no-replace publication. A crash can leave a complete
                    # artifact, reused only after exact readback on safe retry.
                    if os.name == "nt":
                        # Windows rename is atomic and refuses existing targets.
                        os.rename(temporary, target)
                    else:
                        os.link(temporary, target)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
            self.runtime.store.connection.execute("UPDATE initiative_local_grants SET used_at=COALESCE(used_at,?),artifact_path=? WHERE grant_id=?", (now, str(target), grant["grant_id"]))
            self.runtime._record(proposal_id, "LOCAL_HANDOFF_EXPORTED", {"path_digest": digest(str(target)), "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY"}, now)
            return {"path": str(target), "sha256": hashlib.sha256(payload).hexdigest(),
                    "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "contact_authorized": False, "delivery_verified": False}
