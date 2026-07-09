"""Defensive HTTP helpers — block SSRF to private / internal infrastructure.

The capture layer's page-source fetcher
(:mod:`leak_inspector.capture.page_source`) issues HTTP requests to pull
the ``<script>`` bodies a captured page references. Those URLs come from
the live page — untrusted content — so without validation a hostile page
could point the fetch at cloud metadata endpoints (``169.254.169.254``),
loopback debug ports, or RFC1918 LAN services.

This module supplies:

* :func:`is_public_host` — DNS-resolves a host and confirms every
  returned IP is publicly routable (rejects loopback, link-local,
  RFC1918, CGNAT, reserved, multicast, and unspecified ranges; handles
  IPv4-mapped IPv6 like ``::ffff:10.0.0.5`` correctly).
* :func:`is_public_url` — wraps :func:`is_public_host` with scheme
  validation (only ``http`` and ``https``).
* :func:`build_safe_opener` — an ``urllib`` opener whose redirect
  handler re-validates every ``Location`` against :func:`is_public_url`,
  and whose HTTP/HTTPS connections **resolve-and-pin**: the host is
  resolved once at connect time, every answer is validated public, and
  the kernel is handed the already-validated IP literal — there is no
  second resolution for a DNS-rebinding attacker to flip. The original
  hostname stays on the connection object, so the ``Host`` header, TLS
  SNI, and certificate verification all see the real name (virtual
  hosting unaffected). A blocked redirect surfaces the 3xx response to
  the caller without issuing the follow-up request, matching the
  fail-silently semantics of the page-source fetcher; a blocked
  connect raises :class:`NonPublicAddressError` (an ``OSError``, which
  ``urllib`` wraps in ``URLError`` — also fail-silent for the fetcher).

Known trade-off: pinning applies to whatever host the connection is
opened to, so requests routed through a proxy (``http_proxy`` env) are
refused when the *proxy* sits in private address space. The fetcher's
threat model is untrusted script URLs drawn from a captured page;
refusing to tunnel SSRF-sensitive traffic through an unvalidated
private hop is the conservative choice.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.request
from urllib.parse import urlparse

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _ip_is_public(ip: IPAddress) -> bool:
    """Return ``True`` when ``ip`` is in a publicly routable unicast range.

    ``ip.is_global`` already excludes private, loopback, link-local,
    reserved, unspecified and CGNAT (100.64.0.0/10) ranges in one
    check. Multicast is technically "global" but isn't a meaningful
    HTTP destination, so we exclude it explicitly.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        # ::ffff:10.0.0.5 — check the embedded v4 address, not the v6 wrapper,
        # because the kernel will route via the v4 stack.
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def is_public_host(host: str | None) -> bool:
    """Return ``True`` iff ``host`` resolves *only* to public IP addresses.

    Accepts literal IPv4 / IPv6 addresses (including IPv4-mapped IPv6
    like ``::ffff:10.0.0.5``) and hostnames. Hostnames are resolved
    via :func:`socket.getaddrinfo`, which also normalises
    decimal- / octal- / hex-encoded IPv4 forms (e.g. ``2130706433``
    → 127.0.0.1) that :class:`ipaddress.ip_address` rejects but the
    kernel still connects to.

    If *any* resolved address is non-public, the host is refused —
    this is the safe choice for multihomed records that mix public and
    private answers.
    """
    if not host:
        return False
    # urlparse normally strips IPv6 brackets, but be defensive in case a
    # caller passes the raw bracketed form.
    host = host.strip("[]")
    try:
        return _ip_is_public(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    if not infos:
        return False
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if not _ip_is_public(ip):
            return False
    return True


def is_public_url(url: str) -> bool:
    """Return ``True`` iff ``url`` uses ``http`` / ``https`` and resolves publicly."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    return is_public_host(parsed.hostname)


class NonPublicAddressError(OSError):
    """Raised when a connect-time resolution yields a non-public address.

    Subclassing ``OSError`` keeps the probes' fail-silently semantics:
    ``urllib`` wraps it in ``URLError``, which every caller already
    catches.
    """


def _resolve_pinned_addresses(host: str) -> list[str]:
    """Resolve ``host`` once and return its addresses, all validated public.

    The returned IP literals are what the socket layer connects to —
    the single resolution both validates and pins. Raises
    :class:`NonPublicAddressError` when any answer is non-public (the
    rebinding case) and lets ``socket.gaierror`` propagate on
    resolution failure (both are ``OSError``).
    """
    host = host.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not _ip_is_public(ip):
            raise NonPublicAddressError(
                f"refusing connection to non-public address {host}"
            )
        return [host]
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for info in infos:
        candidate = info[4][0]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise NonPublicAddressError(
                f"{host} resolved to unparseable address {candidate!r}"
            ) from exc
        if not _ip_is_public(ip):
            raise NonPublicAddressError(
                f"{host} resolved to non-public {ip} at connect time "
                "(possible DNS rebinding)"
            )
        addresses.append(candidate)
    if not addresses:
        raise NonPublicAddressError(f"{host} resolved to no addresses")
    return addresses


def _pinned_create_connection(address, *args, **kwargs):
    """``socket.create_connection`` with resolve-and-pin semantics.

    Drop-in for :class:`http.client.HTTPConnection`'s
    ``_create_connection`` seam. Tries each validated address in
    resolver order so multi-homed fallback survives the pinning.
    """
    host, port = address
    last_error: OSError | None = None
    for pinned in _resolve_pinned_addresses(host):
        try:
            return socket.create_connection((pinned, port), *args, **kwargs)
        except OSError as exc:
            last_error = exc
    raise last_error  # non-empty list guaranteed above


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose TCP connect goes to a pinned, validated IP."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _pinned_create_connection


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection whose TCP connect goes to a pinned, validated IP.

    Only the TCP step is overridden (via the ``_create_connection``
    seam); the TLS wrap still negotiates against ``self.host``, so SNI
    and certificate verification see the original hostname.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _pinned_create_connection


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    """``urllib`` HTTP handler that opens pinned connections."""

    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """``urllib`` HTTPS handler that opens pinned connections."""

    def https_open(self, req):
        return self.do_open(
            _PinnedHTTPSConnection, req, context=self._context,
        )


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow non-public redirects.

    Returning ``None`` from :meth:`redirect_request` instructs urllib
    to stop following and surface the 3xx response to the caller.
    That matches the audit-friendly behaviour we want: a malicious
    ``302 Location: http://169.254.169.254/...`` is recorded as
    "server returned a 3xx" rather than silently followed.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_public_url(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_safe_opener() -> urllib.request.OpenerDirector:
    """Build an :class:`OpenerDirector` with SSRF-checked redirects and
    resolve-and-pin connections (DNS-rebinding defense)."""
    return urllib.request.build_opener(
        _PinnedHTTPHandler(),
        _PinnedHTTPSHandler(),
        _SafeRedirectHandler(),
    )


__all__ = [
    "NonPublicAddressError",
    "build_safe_opener",
    "is_public_host",
    "is_public_url",
]