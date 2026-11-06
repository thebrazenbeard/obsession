"""Fixed localhost HTTP transport: no proxy, no redirect, no user URL.

A loopback-looking initial URL is insufficient if ambient proxy settings or
HTTP 30x responses can redirect confidential prompts outside the host.
"""
from __future__ import annotations

import urllib.error
import urllib.request

_ALLOWED_METHODS = {
    "http://127.0.0.1:11434/api/chat": "POST",
    "http://127.0.0.1:9147/api/v1/current": "GET",
}


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect rejected for fixed loopback", headers, fp,
        )


def open_fixed_loopback(request: urllib.request.Request, *, timeout: int):
    """Open exactly one approved local endpoint; caller owns closing response."""
    if (not isinstance(request, urllib.request.Request) or
        request.full_url not in _ALLOWED_METHODS or
        request.get_method() != _ALLOWED_METHODS[request.full_url]):
        raise ValueError("endpoint/method not fixed-loopback approved")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _RejectRedirect(),
    )
    return opener.open(request, timeout=timeout)
