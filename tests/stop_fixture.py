"""Disposable test-only lock provider; NOT independently protected on Windows."""
from contextlib import contextmanager
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
