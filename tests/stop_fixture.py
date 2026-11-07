"""Disposable test-only lock provider; NOT independently protected on Windows."""
from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import threading

from resident_initiative.stop_authority import StopAdmission, StopAuthorityUnavailable


class SyntheticStopAuthority:
    def __init__(self):
        self.lock = threading.RLock()
        self.revoked = set()
        self.epoch = 0
        self.error = False
        self.revoke_error = False
        self.override = None

    @contextmanager
    def hold_active(self, *, generation, now):
        with self.lock:
            if self.error:
                raise OSError("test witness outage")
            if generation in self.revoked:
                raise StopAuthorityUnavailable("REVOKED_BY_INDEPENDENT_STOP")
            admission = self.override or StopAdmission(
                generation=generation, epoch=self.epoch, expires_at=now+30,
                scope="LOCAL_SYNTHETIC_HANDOFF_ONLY", decision="ACTIVE")
            yield admission

    def revoke(self, *, generation, now):
        with self.lock:
            if self.revoke_error:
                raise OSError("synthetic witness revoke outage")
            self.revoked.add(generation)
            self.epoch += 1


class SyntheticPublishCustodian(SyntheticStopAuthority):
    """Test-only service-owned publisher, NOT a real protected principal."""
    def __init__(self, output_root):
        super().__init__()
        self.output_root = Path(output_root).resolve()
        self._test_operator_key = b"disposable-synthetic-only-operator-key-0001"

    def operator_sign_for_test(self, grant):
        body = json.dumps(grant, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
        return hmac.new(self._test_operator_key,
                        b"OBSESSION_LOCAL_PUBLISH_GRANT_V1\0" + body,
                        hashlib.sha256).hexdigest()

    def publish_local(self, *, generation, artifact_id, source_digest,
                      payload, grant, grant_mac, now):
        with self.lock:
            if self.error or generation in self.revoked:
                raise StopAuthorityUnavailable("TEST_CUSTODIAN_STOPPED")
            if hashlib.sha256(payload).hexdigest() != source_digest:
                raise StopAuthorityUnavailable("TEST_ARTIFACT_DIGEST_MISMATCH")
            if not hmac.compare_digest(self.operator_sign_for_test(grant),
                                       str(grant_mac)):
                raise StopAuthorityUnavailable("TEST_UNSIGNED_GRANT")
            if (grant["generation"] != generation
                    or grant["artifact_id"] != artifact_id
                    or grant["source_digest"] != source_digest
                    or grant["expires_at"] <= now):
                raise StopAuthorityUnavailable("TEST_GRANT_MISMATCH")
            # This fixture writes as the imaginary privileged server.
            self.output_root.mkdir(parents=True, exist_ok=True)
            target = self.output_root / (artifact_id + ".json")
            if target.exists():
                if target.read_bytes() != payload:
                    raise RuntimeError("divergent custodian artifact")
                state = "ALREADY_IDENTICAL"
            else:
                target.write_bytes(payload)
                state = "PUBLISHED"
            return {"state": state, "path": str(target),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "epoch": self.epoch, "generation": generation}
