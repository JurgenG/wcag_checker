# leak_inspector — record what data a website leaks during a real
# human-driven browsing session.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""TLS-quality probe (enrichment phase, NIS2 cryptography posture).

NIS2 Art. 21(2)(h) asks for cryptography/encryption policies; the CCB
CyberFundamentals external-scan layer checks TLS quality directly. This
probe asks four questions of the landing host's TLS endpoint, once, at
enrichment time:

* Does the certificate chain validate against the system trust store,
  and if not, why (expired / self-signed / untrusted CA / hostname
  mismatch)?
* When does the certificate expire (and how many days from now)?
* What protocol and cipher does a modern client negotiate?
* Are the deprecated TLS 1.0 / 1.1 still accepted?

Certain-data rule (CLAUDE.md): a *valid* chain yields full certificate
metadata via :meth:`ssl.SSLSocket.getpeercert`; an *invalid* chain
yields only the verify-error reason (which already names the fault) plus
the negotiated protocol/cipher from an unverified reconnect — stdlib
``ssl`` will not decode an unvalidated certificate into the dict form,
and the project carries no ASN.1 parser. Legacy-protocol support is a
**three-state** verdict — ``"accepted"`` / ``"rejected"`` /
``"untestable"`` — because a modern client OpenSSL (3.x) often refuses
to even offer TLS 1.0/1.1, so the probe cannot always reach a verdict;
``"untestable"`` is recorded rather than guessed, and only ``"accepted"``
is ever treated as a finding.

The connector is injected for tests so the unit suite is hermetic; the
default uses stdlib ``ssl`` + ``socket`` with a short timeout, gated and
pinned through :func:`leak_inspector.safe_net.is_public_host` (the host
comes from an untrusted bundle manifest).
"""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from ..safe_net import is_public_host

#: Per-handshake timeout. Short, because failure is informative.
_PROBE_TIMEOUT_SECONDS = 5

#: How far ahead a forced-version handshake reaches.
_LEGACY_VERSIONS = (
    ("legacy_tls10", ssl.TLSVersion.TLSv1),
    ("legacy_tls11", ssl.TLSVersion.TLSv1_1),
)

#: ``ssl.TLSVersion`` -> the string :meth:`ssl.SSLSocket.version` reports,
#: used to confirm a forced-legacy handshake really used that version.
_VERSION_NAMES = {
    ssl.TLSVersion.TLSv1: "TLSv1",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
}


@dataclass(frozen=True)
class HandshakeResult:
    """One handshake attempt's outcome — the connector seam's return type.

    ``outcome`` is one of:

    * ``"ok"`` — handshake completed (chain validated when verifying).
    * ``"cert_invalid"`` — TLS was reached but the chain failed to
      validate; ``verify_error`` carries the reason.
    * ``"server_refused"`` — TCP connected but the server declined the
      TLS handshake (protocol/cipher mismatch).
    * ``"client_refused"`` — the local ``ssl`` stack would not attempt
      the requested version (legacy disabled in the build).
    * ``"unreachable"`` — non-public host, DNS failure, connect timeout.
    """

    outcome: str
    protocol: str = ""
    cipher: str = ""
    cert: dict | None = None
    verify_error: str = ""


@dataclass(frozen=True)
class TLSPosture:
    """Captured host's TLS posture, point-in-time.

    ``connected`` is ``True`` when the host speaks TLS at all (a valid
    *or* invalid certificate was presented). ``verify_error`` is empty
    when the chain validated; otherwise it names the fault. The
    ``cert_*`` / ``days_until_expiry`` fields are populated only for a
    valid chain (see module docstring). Each ``legacy_*`` field is one
    of ``"accepted"`` / ``"rejected"`` / ``"untestable"``.
    """

    host: str
    connected: bool
    protocol: str = ""
    cipher: str = ""
    cert_not_before: str = ""
    cert_not_after: str = ""
    days_until_expiry: int | None = None
    issuer: str = ""
    subject_cn: str = ""
    verify_error: str = ""
    legacy_tls10: str = "untestable"
    legacy_tls11: str = "untestable"


#: One handshake attempt: ``(host, port, verify, version) -> HandshakeResult``.
#: ``version`` is ``None`` for a modern handshake or a forced
#: :class:`ssl.TLSVersion` for a legacy probe.
Connector = Callable[[str, int, bool, "ssl.TLSVersion | None"], HandshakeResult]


def probe_tls(
    host: str,
    *,
    port: int = 443,
    connector: Connector | None = None,
    now: datetime | None = None,
) -> TLSPosture | None:
    """Probe ``host``'s TLS endpoint once; return its :class:`TLSPosture`.

    Returns ``None`` only when there is no host to probe. An unreachable
    host yields a posture with ``connected=False`` (itself a signal).
    Never raises: connector failures are absorbed into the outcome.
    """
    if not host:
        return None
    connect: Connector = connector or _live_connector
    now = now or datetime.now(timezone.utc)

    main = connect(host, port, True, None)
    if main.outcome == "ok":
        return _posture_from_valid(host, main, connect, port, now)
    if main.outcome == "cert_invalid":
        return _posture_from_invalid(host, main, connect, port)
    # No working TLS at all — nothing to read, legacy can't be tested.
    return TLSPosture(host=host, connected=False)


# ---------------------------------------------------------------------------
# Orchestration helpers
# ---------------------------------------------------------------------------


def _posture_from_valid(host, main, connect, port, now) -> TLSPosture:
    """Posture for a host whose certificate chain validated."""
    not_before, not_after, days, issuer, subject_cn = _parse_cert(main.cert, now)
    legacy = _probe_legacy(host, connect, port)
    return TLSPosture(
        host=host, connected=True,
        protocol=main.protocol, cipher=main.cipher,
        cert_not_before=not_before, cert_not_after=not_after,
        days_until_expiry=days, issuer=issuer, subject_cn=subject_cn,
        verify_error="", **legacy,
    )


def _posture_from_invalid(host, main, connect, port) -> TLSPosture:
    """Posture for a host that speaks TLS but failed chain validation.

    Reconnect without verification to recover the negotiated
    protocol/cipher (stdlib ``ssl`` cannot decode the certificate dict
    for an unvalidated cert, so the ``cert_*`` fields stay empty).
    """
    plain = connect(host, port, False, None)
    protocol = plain.protocol if plain.outcome in _TLS_REACHED else main.protocol
    cipher = plain.cipher if plain.outcome in _TLS_REACHED else main.cipher
    legacy = _probe_legacy(host, connect, port)
    return TLSPosture(
        host=host, connected=True,
        protocol=protocol, cipher=cipher,
        verify_error=main.verify_error, **legacy,
    )


#: Outcomes that mean the TLS layer was reached (a cert was presented).
_TLS_REACHED = frozenset({"ok", "cert_invalid"})


def _probe_legacy(host, connect, port) -> dict[str, str]:
    """Force a TLS 1.0 and a TLS 1.1 handshake; map each to a verdict."""
    out: dict[str, str] = {}
    for field_name, version in _LEGACY_VERSIONS:
        out[field_name] = _legacy_state(connect(host, port, False, version))
    return out


def _legacy_state(result: HandshakeResult) -> str:
    """Map a forced-version handshake outcome to the three-state verdict.

    A completed handshake means the deprecated version is *accepted*; a
    server-side refusal means it is *rejected*; anything ambiguous
    (the local stack would not offer it, the connection dropped) is
    *untestable* — the conservative choice that never over-claims a
    good posture.
    """
    if result.outcome == "ok":
        return "accepted"
    if result.outcome == "server_refused":
        return "rejected"
    return "untestable"


def _parse_cert(cert: dict | None, now: datetime):
    """Extract ``(not_before, not_after, days, issuer, subject_cn)``.

    Returns empty strings / ``None`` when ``cert`` is absent or a field
    can't be parsed — the probe never raises on a malformed certificate.
    """
    if not cert:
        return "", "", None, "", ""
    not_before = _cert_time_iso(cert.get("notBefore"))
    not_after_dt = _cert_time_dt(cert.get("notAfter"))
    not_after = _to_iso(not_after_dt)
    days = (not_after_dt - now).days if not_after_dt is not None else None
    issuer = (
        _rdn_value(cert.get("issuer"), "organizationName")
        or _rdn_value(cert.get("issuer"), "commonName")
    )
    subject_cn = _rdn_value(cert.get("subject"), "commonName")
    return not_before, not_after, days, issuer, subject_cn


def _rdn_value(rdn_seq, key: str) -> str:
    """Pull a named attribute from a ``getpeercert`` RDN sequence."""
    if not rdn_seq:
        return ""
    for rdn in rdn_seq:
        for attr in rdn:
            if len(attr) == 2 and attr[0] == key:
                return str(attr[1])
    return ""


def _cert_time_dt(value: str | None) -> datetime | None:
    """Parse an OpenSSL cert timestamp (e.g. ``"Sep  1 00:00:00 2026 GMT"``)."""
    if not value:
        return None
    try:
        epoch = ssl.cert_time_to_seconds(value)
    except (ValueError, TypeError):
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _cert_time_iso(value: str | None) -> str:
    return _to_iso(_cert_time_dt(value))


def _to_iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Default (live) connector
# ---------------------------------------------------------------------------

#: OpenSSL error fragments that mean the *peer* declined the version
#: (a genuine "rejected"), as opposed to the local stack refusing to
#: offer it. Matched case-insensitively against the error text.
_SERVER_REFUSAL_MARKERS = (
    "alert protocol version",
    "tlsv1 alert",
    "sslv3 alert",
    "handshake failure",
)


def _live_connector(
    host: str, port: int, verify: bool, version: "ssl.TLSVersion | None",
) -> HandshakeResult:
    """Default connector: one stdlib ``ssl`` handshake, pinned to a
    validated public IP (SNI/verification still see the real hostname).

    Soft-fail: every failure maps to a :class:`HandshakeResult` outcome
    rather than raising, so :func:`probe_tls` stays exception-free.
    """
    if not is_public_host(host):
        return HandshakeResult(outcome="unreachable")
    try:
        ctx = _build_context(verify, version)
    except (ValueError, ssl.SSLError):
        # Local stack won't even configure this version (legacy disabled).
        return HandshakeResult(outcome="client_refused")

    try:
        addrinfos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return HandshakeResult(outcome="unreachable")

    last = HandshakeResult(outcome="unreachable")
    for info in addrinfos:
        ip = info[4][0]
        if not is_public_host(ip):  # validate each literal before pinning
            continue
        try:
            with socket.create_connection(
                (ip, port), timeout=_PROBE_TIMEOUT_SECONDS,
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    negotiated = tls.version() or ""
                    # Defend against a build that ignores the version pin:
                    # a forced-legacy handshake only counts when the
                    # negotiated version is actually the one we asked for.
                    if version is not None \
                            and negotiated != _VERSION_NAMES.get(version):
                        return HandshakeResult(outcome="client_refused")
                    cipher = tls.cipher()
                    return HandshakeResult(
                        outcome="ok",
                        protocol=negotiated,
                        cipher=cipher[0] if cipher else "",
                        cert=tls.getpeercert() if verify else None,
                    )
        except ssl.SSLCertVerificationError as exc:
            return HandshakeResult(
                outcome="cert_invalid", verify_error=_clean_reason(exc),
            )
        except ssl.SSLError as exc:
            last = HandshakeResult(outcome=_classify_ssl_error(exc))
        except OSError:
            last = HandshakeResult(outcome="unreachable")
    return last


def _build_context(verify: bool, version: "ssl.TLSVersion | None") -> ssl.SSLContext:
    """Build the handshake context; raises when a version can't be set."""
    if verify:
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        # Pinning to a deprecated version is the whole point of this
        # probe; silence the stdlib's DeprecationWarning for the assignment.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
        try:
            # Legacy versions need the lowered security level to be offered
            # at all; harmless on builds that ignore it.
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return ctx


def _classify_ssl_error(exc: ssl.SSLError) -> str:
    """Decide whether a handshake SSLError is a server or client refusal.

    Conservative: only a recognised peer-side protocol alert counts as
    ``"server_refused"`` (a genuine rejection); everything else is
    treated as a local refusal, which maps to ``"untestable"`` so the
    probe never over-claims a good legacy posture.
    """
    text = str(exc).lower()
    if any(marker in text for marker in _SERVER_REFUSAL_MARKERS):
        return "server_refused"
    return "client_refused"


def _clean_reason(exc: ssl.SSLCertVerificationError) -> str:
    """A short, human verify-error reason (e.g. ``"certificate has expired"``)."""
    reason = getattr(exc, "verify_message", "") or getattr(exc, "reason", "")
    return str(reason) if reason else str(exc)


__all__ = ["Connector", "HandshakeResult", "TLSPosture", "probe_tls"]
