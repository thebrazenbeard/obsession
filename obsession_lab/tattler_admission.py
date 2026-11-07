"""Bounded, read-only Tattler event *candidate* admission; never action authority.

The actual Tattler HTTP endpoints do not authenticate callers or their source
claims. This pure adapter is intended for a host-owned observation boundary;
passing the data below does NOT attest the endpoint or make an old `open`
event proof that a listener is still present. No network I/O occurs here.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import re
from threading import RLock


_ID = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_PORT = re.compile(r"[0-9]{1,5}\Z")
_EVENT_KEYS = {"schema_version", "event_id", "observed_at", "host", "kind", "source", "connection"}
_CONNECTION_KEYS = {"kind", "protocol", "local", "remote", "state", "direction",
                    "inode", "uid", "owner", "process"}


@dataclass(frozen=True)
class AdmissionPolicy:
    expected_host: str
    expected_source: str
    declared_local_ports: frozenset[int]
    max_age_seconds: int = 120
    future_skew_seconds: int = 5

    def __post_init__(self):
        if (not isinstance(self.expected_host, str) or not _IDENTITY.fullmatch(self.expected_host)
                or not isinstance(self.expected_source, str) or not _IDENTITY.fullmatch(self.expected_source)):
            raise ValueError("invalid declared Tattler fixture identity")
        if (not isinstance(self.declared_local_ports, frozenset)
                or not self.declared_local_ports or len(self.declared_local_ports) > 32
                or any(type(p) is not int or p < 1 or p > 65535 for p in self.declared_local_ports)):
            raise ValueError("invalid explicit loopback port inventory")
        if (type(self.max_age_seconds) is not int or not 1 <= self.max_age_seconds <= 3600
                or type(self.future_skew_seconds) is not int or not 0 <= self.future_skew_seconds <= 30):
            raise ValueError("invalid freshness window")


@dataclass
class ReplayLedger:
    """Ephemeral, bounded in-process dedup. No restart/replay guarantee."""
    max_entries: int = 4096
    _seen: OrderedDict[str, str] = field(default_factory=OrderedDict, init=False, repr=False)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def __post_init__(self):
        if type(self.max_entries) is not int or not 1 <= self.max_entries <= 16384:
            raise ValueError("invalid replay ledger bound")


def _time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("invalid event timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError("invalid event timestamp") from e
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("naive event timestamp")
    return parsed.astimezone(timezone.utc)


def _loopback_port(local: object) -> int:
    if not isinstance(local, str) or len(local) > 128:
        raise ValueError("invalid local endpoint")
    if local.startswith("["):
        index = local.find("]:")
        if index < 0:
            raise ValueError("invalid local endpoint")
        address, digits = local[1:index], local[index+2:]
    else:
        address, separator, digits = local.partition(":")
        if separator != ":":
            raise ValueError("invalid local endpoint")
    if not _PORT.fullmatch(digits):
        raise ValueError("invalid local port")
    try:
        addr = ipaddress.ip_address(address)
    except ValueError as e:
        raise ValueError("invalid local address") from e
    port = int(digits)
    if not addr.is_loopback or not 1 <= port <= 65535:
        raise ValueError("not an eligible loopback listener")
    return port


def admit_tattler_events(
    events: object, *, policy: AdmissionPolicy, ledger: ReplayLedger, now: datetime
) -> dict:
    """Validate source claims and emit only redacted *advisory* open events.

    `policy` and `ledger` must be owned by the host integration, never created
    from model-provided arguments. Even then, the source's HTTP transport is
    unauthenticated; this routine grants no execution or recipient authority.
    """
    if not isinstance(policy, AdmissionPolicy) or not isinstance(ledger, ReplayLedger):
        raise TypeError("host-owned admission dependencies required")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("timezone-aware evaluation time required")
    if not isinstance(events, list) or len(events) > 128:
        raise ValueError("invalid Tattler event batch")
    try:
        encoded = json.dumps(events, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as e:
        raise ValueError("invalid JSON event payload") from e
    if len(encoded) > 65536:
        raise ValueError("Tattler event batch too large")

    evaluation = now.astimezone(timezone.utc)
    verified: list[tuple[str, str, dict | None]] = []
    for event in events:
        if not isinstance(event, dict) or set(event) != _EVENT_KEYS:
            raise ValueError("unexpected Tattler event schema")
        if type(event["schema_version"]) is not int or event["schema_version"] != 1:
            raise ValueError("unsupported Tattler event schema")
        event_id = event["event_id"]
        if not isinstance(event_id, str) or not _ID.fullmatch(event_id):
            raise ValueError("invalid event identifier")
        if event["host"] != policy.expected_host or event["source"] != policy.expected_source:
            raise ValueError("unexpected Tattler source claim")
        observed_at = _time(event["observed_at"])
        delay = (evaluation - observed_at).total_seconds()
        if delay > policy.max_age_seconds or delay < -policy.future_skew_seconds:
            raise ValueError("stale or future Tattler event")
        if event["kind"] not in ("open", "close"):
            raise ValueError("unexpected Tattler event kind")
        c = event["connection"]
        if not isinstance(c, dict) or not set(c).issubset(_CONNECTION_KEYS):
            raise ValueError("unexpected Tattler connection schema")
        candidate = None
        if event["kind"] == "open" and c.get("kind") == "tcp_listener":
            if c.get("protocol") not in ("tcp", "tcp6") or c.get("direction") != "listen":
                raise ValueError("not an eligible TCP listener observation")
            if c.get("state") not in ("LISTEN", "LISTENING"):
                raise ValueError("listener state inconsistent with claimed event")
            port = _loopback_port(c.get("local"))
            if port not in policy.declared_local_ports:
                raise ValueError("listener port not in host-declared inventory")
            candidate = {"event_id": event_id, "port": port,
                         "status": "RECENT_OPEN_EVENT_NOT_CURRENT_LISTENER_PROOF"}
        fingerprint = sha256(json.dumps(event, sort_keys=True, separators=(",", ":"),
                                        allow_nan=False).encode("utf-8")).hexdigest()
        verified.append((event_id, fingerprint, candidate))

    # Commit the dedup state atomically only if the whole batch is valid.
    with ledger._lock:
        pending: OrderedDict[str, str] = OrderedDict()
        candidates: list[dict] = []
        replay_count = 0
        for event_id, fingerprint, candidate in verified:
            previous = pending.get(event_id, ledger._seen.get(event_id))
            if previous is not None:
                if previous != fingerprint:
                    raise ValueError("conflicting reuse of Tattler event identifier")
                replay_count += 1
                continue
            pending[event_id] = fingerprint
            if candidate is not None:
                candidates.append(candidate)
        ledger._seen.update(pending)
        while len(ledger._seen) > ledger.max_entries:
            ledger._seen.popitem(last=False)

    return {
        "schema": "obsession.tattler-event-admission.v1",
        "source_class": "UNAUTHENTICATED_TATTLER_EVENT_CLAIM",
        "candidate_events": candidates,
        "replay_count": replay_count,
        "source_authenticated": False,
        "current_listener_verified": False,
        "recipient_verified": False,
        "execution_authorized": False,
        "execution_count": 0,
        "message_delivered": False,
        "persistence": "NONE",
    }
