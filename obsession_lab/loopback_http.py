"""Fixed localhost HTTP transport: no proxy, no redirect, no user URL.

A loopback-looking initial URL is insufficient if ambient proxy settings or
HTTP 30x responses can redirect confidential prompts outside the host.
"""
from __future__ import annotations

import urllib.error
import urllib.request

_ALLOWED_TARGETS = {
    "http://127.0.0.1:11434/api/chat": ("POST", "127.0.0.1:11434", "/api/chat"),
    "http://127.0.0.1:9147/api/v1/current": ("GET", "127.0.0.1:9147", "/api/v1/current"),
}


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect rejected for fixed loopback", headers, fp,
        )


def open_fixed_loopback(request: urllib.request.Request, *, timeout: int):
    """Open one fixed target with sanitized request metadata; caller closes reply."""
    if not isinstance(request, urllib.request.Request):
        raise ValueError("request must be urllib.Request")
    allowed = _ALLOWED_TARGETS.get(request.full_url)
    if allowed is None:
        raise ValueError("unapproved loopback endpoint")
    method, host, selector = allowed
    if (request.get_method() != method or request.host != host or
        request.selector != selector or request.has_proxy() or
        any(k.casefold() not in {"content-type"} for k, _ in request.header_items())):
        raise ValueError("mutated request host/proxy/method/header")
    if method == "POST":
        if not isinstance(request.data, bytes):
            raise ValueError("POST must carry bytes")
        headers = {"Content-Type": "application/json"}
    else:
        if request.data is not None:
            raise ValueError("GET cannot carry a body")
        headers = {}
    # Do not forward the caller-owned mutable Request to the socket layer.
    clean = urllib.request.Request(request.full_url, data=request.data,
                                   headers=headers, method=method)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _RejectRedirect(),
    )
    return opener.open(clean, timeout=timeout)
