"""Optional Tattler observation to communication opportunity *candidates*.

A network listener is not a messaging capability. No send/tool invocation.
"""
from __future__ import annotations
from dataclasses import dataclass,asdict
from datetime import datetime
import ipaddress
import json
import re
import urllib.request

from .loopback_http import open_fixed_loopback
from .tattler_admission import AdmissionPolicy, ReplayLedger, admit_tattler_events

_ENDPOINT = "http://127.0.0.1:9147/api/v1/current"
_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_MAX_BYTES=262144


@dataclass(frozen=True)
class DeclaredChannel:
    channel_id: str
    local_port: int
    authorized_for_outbound: bool = False

    def __post_init__(self):
        if not isinstance(self.channel_id,str) or not _ID.fullmatch(self.channel_id):
            raise ValueError("channel_id invalid")
        if type(self.local_port) is not int or not 1 <= self.local_port <= 65535:
            raise ValueError("port invalid")
        if type(self.authorized_for_outbound) is not bool:
            raise ValueError("outbound flag invalid")


def _loopback_port(value: object) -> int | None:
    if not isinstance(value,str) or len(value)>128:
        return None
    try:
        host,port = value.rsplit(":",1)
        host=host.strip("[]")
        if not ipaddress.ip_address(host).is_loopback:
            return None
        number=int(port)
        return number if 1<=number<=65535 else None
    except (ValueError, IndexError):
        return None


def candidate_routes(observations: object, channels: list[DeclaredChannel]) -> dict:
    """A bounded, non-executing correlation to declared local channel ports."""
    if (not isinstance(observations,list) or len(observations)>5000 or
        not isinstance(channels,list) or len(channels)>64 or
        any(not isinstance(c,DeclaredChannel) for c in channels)):
        raise ValueError("invalid observation/channel collection")
    candidate_ports=set()
    for record in observations:
        if not isinstance(record,dict):
            continue
        if (record.get("kind")!="tcp_listener" or
            record.get("direction")!="listen" or
            record.get("state") not in ("LISTEN", "LISTENING")):
            continue
        port=_loopback_port(record.get("local"))
        if port is not None:
            candidate_ports.add(port)
    matches=[]
    for channel in channels:
        if channel.local_port in candidate_ports:
            matches.append({
                "channel_id":channel.channel_id,
                "status":"LOCAL_LISTENER_OBSERVED_ONLY",
                "port":channel.local_port,
                "transport_looks_available":True,
                "channel_authenticated":False,
                "send_attempted":False,
                "outbound_permission_declared":channel.authorized_for_outbound,
                "outbound_permission_verified":False,
                "recipient_verified":False,
                "next":"Confirm provider identity, authenticated session, recipient and exact send scope before action",
            })
    return {
        "schema":"obsession.channel-candidates.v1",
        "source_class":"TATTLER_SAMPLED_NETWORK_UNAUTHENTICATED",
        "candidates":matches,
        "execution_count":0,
        "message_delivered":False,
        "effects_authorized":False,
    }


def candidate_routes_from_tattler_events(
    events: object, channels: list[DeclaredChannel], *,
    policy: AdmissionPolicy, ledger: ReplayLedger, now: datetime,
) -> dict:
    """Pure advisory crosswalk from admitted recent events to declared ports.

    A recent open event is weaker than a current listener snapshot. A source
    claim and host inventory are not identity attestation or send authority.
    Host code must own policy, ledger, evaluation clock, and source intake.
    """
    if (not isinstance(policy, AdmissionPolicy) or
        not isinstance(ledger, ReplayLedger) or
        not isinstance(channels, list)):
        raise ValueError("invalid host-owned admission dependencies/channels")
    # Snapshot the caller's mutable list before validation/admission/iteration.
    # Concurrent catalog mutation must not consume an event without mapping it.
    channel_snapshot = tuple(channels)
    if (not channel_snapshot or len(channel_snapshot) > 64 or
        any(not isinstance(c, DeclaredChannel) for c in channel_snapshot)):
        raise ValueError("invalid host-owned channel snapshot")
    # Bind the ledger to a complete host channel-port catalog. A partial
    # catalog would consume an unmatched event; after a catalog update, that
    # very same observation would be suppressed as replay and silently lost.
    if (len({c.channel_id for c in channel_snapshot}) != len(channel_snapshot) or
        {c.local_port for c in channel_snapshot} != policy.declared_local_ports):
        raise ValueError("channel inventory conflicts with host policy")
    admitted = admit_tattler_events(events, policy=policy, ledger=ledger, now=now)
    matches = []
    for recent in admitted["candidate_events"]:
        for channel in channel_snapshot:
            if channel.local_port == recent["port"]:
                matches.append({
                    "channel_id": channel.channel_id, "event_id": recent["event_id"],
                    "port": channel.local_port, "status": recent["status"],
                    "current_listener_verified": False,
                    "channel_authenticated": False, "recipient_verified": False,
                    "outbound_permission_declared": channel.authorized_for_outbound,
                    "outbound_permission_verified": False, "send_attempted": False,
                })
    return {
        "schema": "obsession.event-channel-candidates.v1",
        "source_class": admitted["source_class"],
        "candidates": matches, "replay_count": admitted["replay_count"],
        "source_authenticated": False, "current_listener_verified": False,
        "execution_count": 0, "message_delivered": False,
        "effects_authorized": False,
    }


def fetch_tattler_current(*, timeout_seconds: int=3) -> list[dict]:
    if type(timeout_seconds) is not int or not 1<=timeout_seconds<=10:
        raise ValueError("invalid timeout")
    req=urllib.request.Request(_ENDPOINT,method="GET")
    with open_fixed_loopback(req,timeout=timeout_seconds) as response:
        content=response.read(_MAX_BYTES+1)
    if len(content)>_MAX_BYTES:
        raise ValueError("Tattler response too large")
    data=json.loads(content)
    if not isinstance(data,list) or len(data)>5000:
        raise ValueError("invalid Tattler schema")
    return data