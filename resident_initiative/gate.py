"""Owner-controlled local output gate, separate from model proposal creation.

No recipient, network delivery, phone credentials or device API exists here.
An explicit persisted owner grant binds one proposal digest and local directory.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import uuid

from .runtime import CommitDenial, Runtime, canonical, digest, finite
from .deps import PROVENANCE
from .stop_authority import StopAuthorityUnavailable
from pre_active.engine import ModelResponse


class LocalHandoffGate:
    def __init__(self, runtime):
        self.runtime = runtime

    @staticmethod
    def _handoff_payload(row, proposal):
        """One stable output encoding used both before signing and at publish."""
        return (canonical({"schema": "initiative.local-handoff.v1",
                           "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY",
                           "proposal_digest": row["proposal_digest"], "proposal": proposal,
                           "delivery_verified": False, "contact_authorized": False}) + "\n").encode("utf-8")

    def _publisher(self, directory):
        custodian = getattr(self.runtime, "stop_authority", None)
        if custodian is None or not callable(getattr(custodian, "publish_local", None)):
            raise StopAuthorityUnavailable("PROTECTED_HOST_PUBLISHER_UNAVAILABLE")
        if Path(directory).resolve() != Path(getattr(custodian, "output_root", "")).resolve():
            raise StopAuthorityUnavailable("LOCAL_DIRECTORY_NOT_CUSTODIAN_PROTECTED_ROOT")
        return custodian

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
        """Stage a local candidate grant; only host operator can sign it.

        This SQLite record is not final publication authority. PUBLISH requires
        a separately issued operator-HMAC grant from protected host custody.
        """
        now = self.runtime.clock() if now is None else now
        directory = str(Path(directory).resolve())
        self._publisher(directory)
        with self.runtime.transaction():
            reason = self.runtime._hold_reason(self.runtime._owner(), now)
            if reason:
                raise CommitDenial(reason)
            row = self.runtime.store.connection.execute("SELECT * FROM initiative_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
            if row is None:
                raise KeyError("proposal does not exist")
            proposal = self._verified_proposal(row, now)
            if not now < finite(expires_at, "grant expiry") <= min(self.runtime.config.expires_at, now + 3600):
                raise ValueError("local grant expiry must be fresh and bounded")
            grant_id = str(uuid.uuid4())
            self.runtime.store.connection.execute("INSERT INTO initiative_local_grants VALUES(?,?,?,?,?,?,NULL,NULL)",
                                          (grant_id, proposal_id, row["proposal_digest"], self.runtime.generation, directory, expires_at))
        host_grant_request = {"generation": self.runtime.generation,
                              "artifact_id": proposal_id.removeprefix("sha256:"),
                              "source_digest": hashlib.sha256(self._handoff_payload(row, proposal)).hexdigest(),
                              "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY",
                              "expires_at": float(expires_at)}
        return {"schema": "initiative.local-grant.v1", "grant_id": grant_id,
                "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "proposal_id": proposal_id,
                "proposal_digest": row["proposal_digest"], "generation": self.runtime.generation,
                "directory": directory, "expires_at": expires_at, "contact_authorized": False,
                "host_grant_request": host_grant_request}

    def export(self, proposal_id, grant_path, directory, *, now=None):
        """Publish only through a separately protected host custodian.

        This process may read/check its SQLite state, but it never writes the
        final artifact. A local lease and os.link would be bypassable by a
        resident principal that can write the target directory directly.
        """
        now = self.runtime.clock() if now is None else now
        grant_file = json.loads(Path(grant_path).read_text(encoding="utf-8"))
        if type(grant_file) is not dict or grant_file.get("scope") != "LOCAL_SYNTHETIC_HANDOFF_ONLY":
            raise PermissionError("explicit local synthetic grant required")
        target_directory = Path(directory).resolve()
        custodian = self._publisher(target_directory)
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
                    or grant_file.get("proposal_digest") != row["proposal_digest"]
                    or grant_file.get("proposal_id") != proposal_id
                    or grant_file.get("generation") != self.runtime.generation
                    or grant_file.get("directory") != str(target_directory)
                    or grant_file.get("expires_at") != grant["expires_at"]):
                self.runtime._record(proposal_id, "REJECTED_LOCAL_HANDOFF", {"reason": "MISSING_OR_INVALID_HOST_GRANT"}, now)
                raise CommitDenial("local handoff grant is invalid")
            payload = self._handoff_payload(row, proposal)
            # An operator must independently sign this exact host-bound grant.
            # No resident code may mint a protected grant MAC itself.
            artifact_id = proposal_id.removeprefix("sha256:")
            source_digest = hashlib.sha256(payload).hexdigest()
            host_grant = {"generation": self.runtime.generation,
                          "artifact_id": artifact_id,
                          "source_digest": source_digest,
                          "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY",
                          "expires_at": float(grant["expires_at"])}
            if grant_file.get("host_grant_request") != host_grant:
                raise StopAuthorityUnavailable("HOST_GRANT_BINDING_MISMATCH")
            receipt = custodian.publish_local(
                generation=self.runtime.generation,
                artifact_id=artifact_id,
                source_digest=source_digest,
                payload=payload,
                grant=host_grant,
                grant_mac=grant_file.get("host_grant_mac"),
                now=now)
            target = str(receipt["path"])
            self.runtime.store.connection.execute("UPDATE initiative_local_grants SET used_at=COALESCE(used_at,?),artifact_path=? WHERE grant_id=?", (now, target, grant["grant_id"]))
            self.runtime._record(proposal_id, "LOCAL_HANDOFF_EXPORTED", {"path_digest": digest(target), "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY"}, now)
            return {"path": target, "sha256": hashlib.sha256(payload).hexdigest(),
                    "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY", "contact_authorized": False, "delivery_verified": False}

