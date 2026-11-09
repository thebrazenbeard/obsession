"""Source-only resident PUBLISH adapter for the native Windows STOP custodian.

This module never sends STOP, GRANT, or REGISTER. Those commands belong on a
separate, administrator/operator-only named pipe. The server, not this client,
owns the final artifact and decides whether an independent grant is valid.

Transport qualification on the actual Windows identity remains outstanding.
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import re
import time
from pathlib import PureWindowsPath


PUBLISH_PIPE = r"\\.\pipe\VeraObsessionStopPublishV1"
OUTPUT_ROOT = r"C:\Program Files\VERA\ObsessionStopCustodian\output"
_GENERATION = re.compile(r"\A[a-zA-Z0-9_-]{8,96}\Z")
_DIGEST = re.compile(r"\A[a-f0-9]{64}\Z")
_PROPOSAL_DIGEST = re.compile(r"\Asha256:[a-f0-9]{64}\Z")
_HANDOFF_KEYS = frozenset(("schema", "scope", "proposal_digest", "proposal",
                           "delivery_verified", "contact_authorized"))
_SERVICE_NAME = "VeraObsessionStopCustodian"


class NativeStopDenied(PermissionError):
    """A refusal or absence of independently protected publication authority."""


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _no_constants(value):
    raise ValueError("nonfinite JSON constant: " + value)


def validate_handoff(payload):
    """Reject contact-bearing and malformed resident output before IPC.

    The server must independently perform its own validation; this is defense
    in depth, not a trust boundary.
    """
    if type(payload) is not bytes or not 1 <= len(payload) <= 4096:
        raise NativeStopDenied("LOCAL_SYNTHETIC_PAYLOAD_BOUND")
    if not payload.endswith(b"\n"):
        raise NativeStopDenied("HANDOFF_TERMINATOR_MISSING")
    try:
        envelope = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_pairs,
                              parse_constant=_no_constants)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise NativeStopDenied("INVALID_HANDOFF_JSON") from exc
    if (type(envelope) is not dict or frozenset(envelope) != _HANDOFF_KEYS
            or envelope["schema"] != "initiative.local-handoff.v1"
            or envelope["scope"] != "LOCAL_SYNTHETIC_HANDOFF_ONLY"
            or type(envelope["proposal_digest"]) is not str
            or not _PROPOSAL_DIGEST.fullmatch(envelope["proposal_digest"])
            or envelope["delivery_verified"] is not False
            or envelope["contact_authorized"] is not False):
        raise NativeStopDenied("HANDOFF_SCOPE_OR_INTEGRITY_INVALID")
    proposal = envelope["proposal"]
    if (type(proposal) is not dict or proposal.get("schema") != "initiative.proposal.v1"
            or proposal.get("target_class") != "SYNTHETIC_LOCAL_ONLY"
            or proposal.get("execution_authorized") is not False
            or proposal.get("contact_authorized") is not False
            or proposal.get("delivery_verified") is not False):
        raise NativeStopDenied("PROPOSAL_NOT_SYNTHETIC_ONLY")
    return envelope


def encode_publish(generation, artifact_id, payload):
    """Produce exact unframed UTF-8 command expected by C# PublishCommand.

    `multiprocessing.connection` supplies the 4-byte big-endian length frame.
    """
    if type(generation) is not str or not _GENERATION.fullmatch(generation):
        raise NativeStopDenied("INVALID_GENERATION")
    if type(artifact_id) is not str or not _DIGEST.fullmatch(artifact_id):
        raise NativeStopDenied("INVALID_ARTIFACT_ID")
    validate_handoff(payload)
    wire = ("PUBLISH|" + generation + "|" + artifact_id + "|"
            + base64.b64encode(payload).decode("ascii") + "|V1").encode("utf-8")
    if len(wire) > 8192:
        raise NativeStopDenied("FRAME_TOO_LARGE")
    return wire


def frame(command):
    """Exact native server 4-byte unsigned big-endian length."""
    if type(command) is not bytes or not 1 <= len(command) <= 8192:
        raise NativeStopDenied("INVALID_FRAME")
    return len(command).to_bytes(4, "big") + command


def _attest_windows_pipe_server(handle):
    """Bind an open pipe handle to the exact RUNNING Windows SCM service PID.

    A lookalike named-pipe server can forge PUBLISHED receipts while the real
    service is down. A pipe name or successful connection is not server proof.
    The kernel-reported creator PID for THIS handle must match SCM's running
    SERVICE_WIN32_OWN_PROCESS PID. Windows/admin trust and genuine principal
    separation remain external host qualification requirements.
    """
    # Win32 DWORD is always a 32-bit unsigned integer. ctypes.wintypes.DWORD
    # maps to C unsigned long, which is 64 bits on a Unix LP64 mock host;
    # writing the explicit ABI makes these structural tests discriminating.
    dword = ctypes.c_uint32
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetNamedPipeServerProcessId.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(dword))
    kernel.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    advapi.OpenSCManagerW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR,
                                     dword)
    advapi.OpenSCManagerW.restype = wintypes.HANDLE
    advapi.OpenServiceW.argtypes = (wintypes.HANDLE, wintypes.LPCWSTR,
                                   dword)
    advapi.OpenServiceW.restype = wintypes.HANDLE
    advapi.QueryServiceStatusEx.argtypes = (
        wintypes.HANDLE, dword, ctypes.POINTER(wintypes.BYTE),
        dword, ctypes.POINTER(dword))
    advapi.QueryServiceStatusEx.restype = wintypes.BOOL
    advapi.CloseServiceHandle.argtypes = (wintypes.HANDLE,)
    advapi.CloseServiceHandle.restype = wintypes.BOOL

    class ServiceStatusProcess(ctypes.Structure):
        _fields_ = [(name, dword) for name in (
            "service_type", "current_state", "controls_accepted", "win32_exit_code",
            "service_specific_exit_code", "checkpoint", "wait_hint", "pid",
            "service_flags")]

    server_pid = dword(0)
    if not kernel.GetNamedPipeServerProcessId(wintypes.HANDLE(handle),
                                              ctypes.byref(server_pid)):
        raise OSError(ctypes.get_last_error(), "cannot attest named-pipe peer PID")
    if server_pid.value == 0:
        raise PermissionError("named-pipe peer PID is invalid")

    scm = advapi.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT
    if not scm:
        raise OSError(ctypes.get_last_error(), "cannot query SCM identity")
    service = None
    try:
        service = advapi.OpenServiceW(scm, _SERVICE_NAME, 0x0004)  # SERVICE_QUERY_STATUS
        if not service:
            raise OSError(ctypes.get_last_error(), "cannot identify STOP custodian service")
        status = ServiceStatusProcess()
        needed = dword(0)
        data = ctypes.cast(ctypes.byref(status), ctypes.POINTER(wintypes.BYTE))
        if not advapi.QueryServiceStatusEx(service, 0, data, ctypes.sizeof(status),
                                           ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "cannot query STOP service process")
        # SERVICE_WIN32_OWN_PROCESS=0x10, SERVICE_RUNNING=4.
        if (status.service_type != 0x10 or status.current_state != 4
                or status.pid == 0 or status.pid != server_pid.value):
            raise PermissionError("named-pipe server is not the running STOP service")
    finally:
        if service:
            advapi.CloseServiceHandle(service)
        advapi.CloseServiceHandle(scm)


class NativeNamedPipeChannel:
    """Bounded Windows overlapped byte-pipe transport; Windows test pending.

    Do not use multiprocessing.connection.Client for this protocol. On
    Windows its PipeConnection uses MESSAGE mode and sends raw messages,
    whereas the native C# service uses BYTE mode and its own 4-byte frame.
    """

    def __init__(self, pipe, *, timeout=3.0):
        if pipe != PUBLISH_PIPE or not 0 < timeout <= 10:
            raise ValueError("unexpected pipe or timeout")
        self.pipe = pipe
        self.timeout = timeout
        self.handle = None
        self.api = None
        self.deadline = None

    def __enter__(self):
        import _winapi  # only exists on Windows; deliberate fail-close on Linux
        self.api = _winapi
        self.api.WaitNamedPipe(self.pipe, int(self.timeout * 1000))
        self.handle = self.api.CreateFile(
            self.pipe, self.api.GENERIC_READ | self.api.GENERIC_WRITE,
            0, self.api.NULL, self.api.OPEN_EXISTING,
            self.api.FILE_FLAG_OVERLAPPED, self.api.NULL)
        try:
            # Attest before sending any command or accepting any receipt.
            _attest_windows_pipe_server(self.handle)
        except BaseException:
            self.api.CloseHandle(self.handle)
            self.handle = None
            raise
        self.deadline = time.monotonic() + self.timeout
        # No SetNamedPipeHandleState(..., PIPE_READMODE_MESSAGE): native C#
        # server deliberately uses byte mode.
        return self

    def __exit__(self, *_unused):
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def _finish(self, overlapped, err):
        if err == self.api.ERROR_IO_PENDING:
            try:
                deadline = self.deadline or time.monotonic() + self.timeout
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("native pipe I/O deadline")
                outcome = self.api.WaitForMultipleObjects(
                    [overlapped.event], False, max(1, int(remaining * 1000)))
                if outcome != self.api.WAIT_OBJECT_0:
                    raise TimeoutError("native pipe I/O deadline")
            except BaseException:
                # CancelIoEx requests cancellation; it does not certify that
                # the kernel has stopped using the overlapped I/O buffer.
                # CPython's _winapi.Overlapped.cancel() clears `pending`, so
                # discarding this object before a blocking result drain may
                # prematurely release its read/write buffer. Match the drain
                # convention in CPython multiprocessing.connection.
                try:
                    overlapped.cancel()
                except OSError:
                    pass
                try:
                    overlapped.GetOverlappedResult(True)
                except OSError:
                    pass
                raise
        count, error = overlapped.GetOverlappedResult(True)
        if error:
            raise OSError(error, "native pipe I/O failed")
        return count

    def send_bytes(self, command):
        wire = frame(command)
        overlapped, error = self.api.WriteFile(self.handle, wire, overlapped=True)
        written = self._finish(overlapped, error)
        if written != len(wire):
            raise OSError("incomplete native pipe write")

    def poll(self, timeout):
        deadline = min(time.monotonic() + float(timeout),
                       self.deadline or time.monotonic() + self.timeout)
        while True:
            if self.api.PeekNamedPipe(self.handle)[0] >= 4:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def _read_exact(self, n):
        parts = bytearray()
        while len(parts) < n:
            overlapped, error = self.api.ReadFile(
                self.handle, n - len(parts), overlapped=True)
            length = self._finish(overlapped, error)
            if length <= 0:
                raise EOFError("native pipe closed")
            parts.extend(bytes(overlapped.getbuffer())[:length])
        return bytes(parts)

    def recv_bytes(self, maxlength):
        length = int.from_bytes(self._read_exact(4), "big")
        if not 1 <= length <= maxlength:
            raise ValueError("native pipe response frame invalid")
        return self._read_exact(length)


def _default_connect(pipe):
    return NativeNamedPipeChannel(pipe)


class NativeStopPublishClient:
    """Resident PUBLISH-only client; cannot grant or revoke a generation."""

    def __init__(self, *, connector=_default_connect, timeout=3.0,
                 pipe=PUBLISH_PIPE, output_root=OUTPUT_ROOT):
        if not 0 < float(timeout) <= 10:
            raise ValueError("bounded pipe timeout required")
        if pipe != PUBLISH_PIPE:
            raise ValueError("unexpected PUBLISH pipe")
        if str(output_root) != OUTPUT_ROOT:
            raise ValueError("unexpected protected output root")
        self._connector = connector
        self._timeout = float(timeout)
        self._pipe = pipe
        self.output_root = OUTPUT_ROOT

    def revoke(self, *, generation, now):
        """A resident cannot impersonate the independent STOP operator."""
        raise NativeStopDenied("OPERATOR_STOP_REQUIRED")

    def hold_active(self, *, generation, now):
        """The native service uses final server-owned PUBLISH, not leases."""
        raise NativeStopDenied("LEGACY_STOP_LEASE_UNSUPPORTED")

    def publish_local(self, *, generation, artifact_id, source_digest, payload,
                      grant, grant_mac=None, now=None):
        """Publish with a separately established operator grant; fail closed.

        `grant` is an untrusted resident-side echo, not operator authority.
        C# looks up its own protected GRANT journal and checks the payload hash.
        """
        request = encode_publish(generation, artifact_id, payload)
        actual_digest = hashlib.sha256(payload).hexdigest()
        if type(source_digest) is not str or source_digest != actual_digest:
            raise NativeStopDenied("PAYLOAD_DIGEST_MISMATCH")
        if (type(grant) is not dict or grant.get("generation") != generation
                or grant.get("artifact_id") != artifact_id
                or grant.get("source_digest") != source_digest
                or grant.get("scope") != "LOCAL_SYNTHETIC_HANDOFF_ONLY"
                or type(grant.get("expires_at")) not in (float, int)):
            raise NativeStopDenied("GRANT_ECHO_INVALID")
        if grant_mac is not None:
            # Native ACL-bound operator authority does not support Python MACs.
            # Do not silently accept cross-protocol credentials.
            raise NativeStopDenied("UNSUPPORTED_GRANT_MAC_PROTOCOL")
        current = time.time() if now is None else now
        if not type(current) in (float, int) or not float(current) < grant["expires_at"]:
            raise NativeStopDenied("GRANT_ECHO_EXPIRED")
        try:
            with self._connector(self._pipe) as channel:
                channel.send_bytes(request)
                if not channel.poll(self._timeout):
                    raise NativeStopDenied("CUSTODIAN_RESPONSE_TIMEOUT")
                reply = channel.recv_bytes(maxlength=4096)
                # Native service holds its pipe connected until it receives
                # this transport-only receipt of the exact response bytes.
                # No publication authority is conveyed by ACK. A failed ACK
                # must never be promoted into a successful resident receipt.
                ack = ("ACK|" + hashlib.sha256(reply).hexdigest() + "|V1").encode("ascii")
                channel.send_bytes(ack)
        except NativeStopDenied:
            raise
        except (ImportError, AttributeError, OSError, EOFError,
                BufferError, ValueError, TypeError) as exc:
            # Explicit selection on a non-Windows Python runtime must deny
            # publication when `_winapi` or `ctypes.WinDLL` is unavailable.
            raise NativeStopDenied("CUSTODIAN_PIPE_UNAVAILABLE") from exc
        try:
            answer = reply.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise NativeStopDenied("INVALID_CUSTODIAN_RESPONSE") from exc
        if answer not in ("PUBLISHED|" + artifact_id, "ALREADY_PRESENT|" + artifact_id):
            if answer.startswith("HOLD|"):
                raise NativeStopDenied(answer)
            raise NativeStopDenied("UNEXPECTED_CUSTODIAN_RESPONSE")
        return {"path": str(PureWindowsPath(self.output_root) / (artifact_id + ".json")),
                "receipt": answer, "scope": "LOCAL_SYNTHETIC_HANDOFF_ONLY",
                "contact_authorized": False, "delivery_verified": False}

