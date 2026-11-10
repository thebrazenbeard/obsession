"""Synthetic-only Windows byte-pipe cancellation probe.

Executes the exact client source in memory, replacing only its pipe-name
constant and SCM attestation function. Never opens the production pipe,
queries SCM, installs a service, or touches protected custody.
"""

import base64
import gzip
import hashlib
import os
import sys
import threading
import time
import types
import uuid
import _winapi

raw = gzip.decompress(base64.b64decode(os.environ["WAVE15_SOURCE_ZB64"]))
module = types.ModuleType("wave15_native_stop_client")
exec(compile(raw, "<exact_native_pipe_source>", "exec"), module.__dict__)
sha = hashlib.sha256(raw).hexdigest()
expected = "dfc2ca3145d408e21fc94862aa6a2c8588fb816c808f419e4263180be40662a1"
if sha != expected:
    raise AssertionError("SOURCE_SHA_MISMATCH:" + sha)

name = "\\\\.\\pipe\\VeraObsessionWave15Synthetic-" + uuid.uuid4().hex
module.PUBLISH_PIPE = name
attest_mode = os.environ.get("WAVE15_ATTEST_MODE", "mock")
if attest_mode == "mock":
    module._attest_windows_pipe_server = lambda _h: None  # synthetic only
elif attest_mode != "real":
    raise ValueError("unknown synthetic attestation mode")
module.NativeNamedPipeChannel._fatal_io = False
module.NativeNamedPipeChannel._unsettled_io = []
server_ready = threading.Event()
release = threading.Event()
server_issues = []
server_state = []


def server():
    handle = None
    try:
        # Non-overlapped, process-local synthetic byte-mode endpoint.
        handle = _winapi.CreateNamedPipe(name, 3, 0, 1, 4096, 4096, 1000, _winapi.NULL)
        server_ready.set()
        try:
            _winapi.ConnectNamedPipe(handle, overlapped=False)
        except OSError as e:
            if getattr(e, "winerror", None) != 535:  # ERROR_PIPE_CONNECTED
                raise
        server_state.append("CONNECTED")
        # Deliberately never write; force a pending client ReadFile.
        release.wait(5.0)
    except BaseException as e:
        server_issues.append(repr(e))
        server_ready.set()
    finally:
        if handle is not None:
            try:
                # Closing the synthetic server handle releases this byte-pipe
                # instance; CPython _winapi exposes no DisconnectNamedPipe.
                _winapi.CloseHandle(handle)
            except BaseException as e:
                server_issues.append("CLOSE:" + repr(e))


worker = threading.Thread(target=server, name="synthetic-byte-server", daemon=True)
worker.start()
if not server_ready.wait(2.0):
    raise AssertionError("SYNTHETIC_SERVER_START_TIMEOUT")
if server_issues:
    raise AssertionError("SYNTHETIC_SERVER_FAILED:" + repr(server_issues))

client_exception = []
client_entered = []
def client():
    try:
        with module.NativeNamedPipeChannel(name, timeout=0.20) as channel:
            client_entered.append(True)
            channel._read_exact(4)
        client_exception.append("UNEXPECTED_READ_SUCCESS")
    except BaseException as e:
        client_exception.append(type(e).__name__ + ":" + str(e))

started = time.monotonic()
client_worker = threading.Thread(target=client, name="synthetic-client", daemon=True)
client_worker.start()
client_worker.join(3.0)
elapsed = time.monotonic() - started
was_hung = client_worker.is_alive()
release.set()
worker.join(2.0)

print("SOURCE_SHA256=" + sha)
print("HOST_PYTHON=" + sys.version.split()[0])
print("PIPE_NAMESPACE=PROCESS_LOCAL_SYNTHETIC_ONLY")
print("SCM_ATTESTATION=" + (
    "REAL_READ_ONLY_SYNTHETIC_PEER" if attest_mode == "real"
    else "MOCKED_UNVERIFIED"))
print("PRODUCTION_PIPE_NAME_USED=false")
print("CONTACT_DISABLED=true")
print("SERVER_STATE=" + repr(server_state))
print("CLIENT_OUTCOME=" + repr(client_exception))
print("CLIENT_ELAPSED_MS=" + str(round(elapsed * 1000)))
print("UNSETTLED_QUARANTINE=" + str(len(module.NativeNamedPipeChannel._unsettled_io)))
if was_hung:
    raise AssertionError("CLIENT_CANCEL_DRAIN_BLOCKED_OVER_3000_MS")
if server_issues:
    raise AssertionError("SYNTHETIC_SERVER_FAILURE:" + repr(server_issues))
if worker.is_alive():
    raise AssertionError("SYNTHETIC_SERVER_CLEANUP_TIMEOUT")
if len(client_exception) != 1:
    raise AssertionError("CLIENT_OUTCOME_UNEXPECTED")
if attest_mode == "real":
    if client_entered:
        raise AssertionError("UNAUTHORIZED_SYNTHETIC_PEER_PASSED_SCM_ATTESTATION")
    if not any(client_exception[0].startswith(p) for p in (
        "PermissionError:", "OSError:", "TimeoutError:"
    )):
        raise AssertionError("UNEXPECTED_SCM_ATTESTATION_OUTCOME")
    print("REAL_WIN32_SYNTHETIC_PEER_REJECT=PASS;SCM_READ_ONLY")
else:
    if not any(client_exception[0].startswith(p) for p in (
        "TimeoutError:", "NativeStopDenied:CUSTODIAN_UNSETTLED_IO_HOLD"
    )):
        raise AssertionError("CLIENT_DID_NOT_FAIL_CLOSED")
    print("REAL_WIN32_CANCEL_PROBE=PASS;UNPRIVILEGED_SYNTHETIC_ONLY")
