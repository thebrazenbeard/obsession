"""Fail-closed adapter for a separately governed resident STOP authority.

The resident database, its WAL, and its snapshots are not STOP authority.
The caller must inject an independently protected provider that serializes
owner STOP with every export/grant lease, for the entire critical section.

This is a source contract, *not* an installed or qualified Windows custodian.
The in-process test provider is deliberately unsuitable for deployment.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import math
from typing import ContextManager, Protocol


class StopAuthorityUnavailable(PermissionError):
    """STOP admission cannot be established; deny publication."""


@dataclass(frozen=True)
class StopAdmission:
    generation: str
    epoch: int
    expires_at: float
    scope: str
    decision: str


class IndependentStopAuthority(Protocol):
    def hold_active(self, *, generation: str, now: float) -> ContextManager[StopAdmission]:
        """Hold the same independent serialization primitive used by STOP."""

    def revoke(self, *, generation: str, now: float) -> None:
        """Permanently revoke generation before acknowledging owner STOP."""


@contextmanager
def require_stop_admission(authority, *, generation: str, now: float):
    """Deny unless a lock-held, generation-bound local handoff admission exists.

    A provider is trusted only after separately verifying its OS custody and
    effective process identities.  This function cannot itself prove that an
    injected Python object is independently protected or lock-coherent.
    """
    if authority is None:
        raise StopAuthorityUnavailable("INDEPENDENT_STOP_AUTHORITY_UNAVAILABLE")
    if type(generation) is not str or not generation:
        raise StopAuthorityUnavailable("INVALID_STOP_GENERATION")
    if type(now) not in (int, float) or not math.isfinite(now):
        raise StopAuthorityUnavailable("INVALID_STOP_CLOCK")
    with ExitStack() as stack:
        try:
            lease = authority.hold_active(generation=generation, now=now)
            admission = stack.enter_context(lease)
        except StopAuthorityUnavailable:
            raise
        except Exception as exc:
            raise StopAuthorityUnavailable("STOP_AUTHORITY_ERROR") from exc
        if (type(admission) is not StopAdmission
                or admission.generation != generation
                or type(admission.epoch) is not int or admission.epoch < 0
                or type(admission.expires_at) not in (int, float)
                or not math.isfinite(admission.expires_at)
                or not now < admission.expires_at <= now + 60
                or admission.scope != "LOCAL_SYNTHETIC_HANDOFF_ONLY"
                or admission.decision != "ACTIVE"):
            raise StopAuthorityUnavailable("INVALID_OR_STALE_STOP_ADMISSION")
        yield admission
