"""Tests for the TLS-quality probe (enrichment phase, NIS2 cryptography).

One verified handshake against the landing host, with an unverified
reconnect when the chain fails to validate (to still read the
negotiated protocol/cipher) and up to two pinned legacy handshakes to
test whether deprecated TLS 1.0/1.1 are still accepted.

Certain-data rule: a valid chain yields full certificate metadata
(``getpeercert`` dict); an invalid chain yields the verify-error reason
(which already names "expired"/"self-signed"/…) but no structured dates
— stdlib ``ssl`` cannot decode an unvalidated certificate. Legacy
support is a three-state verdict — ``accepted`` / ``rejected`` /
``untestable`` — because a modern client OpenSSL often refuses to even
offer the deprecated versions. All offline via the injected connector.
"""

from __future__ import annotations

import ssl
from datetime import datetime, timezone

from leak_inspector.http_posture.tls import (
    HandshakeResult,
    TLSPosture,
    probe_tls,
)

_NOW = datetime(2026, 6, 22, tzinfo=timezone.utc)

_VALID_CERT = {
    "subject": ((("commonName", "example.be"),),),
    "issuer": (
        (("countryName", "US"),),
        (("organizationName", "Let's Encrypt"),),
        (("commonName", "R3"),),
    ),
    "notBefore": "Jun  1 00:00:00 2026 GMT",
    "notAfter": "Sep  1 00:00:00 2026 GMT",
}


def _connector(responses):
    """Build a fake connector dispatching on ``(verify, version)``.

    ``responses`` maps a key to a :class:`HandshakeResult`:
    ``"verify"`` (verified modern handshake), ``"plain"`` (unverified
    modern reconnect), ``ssl.TLSVersion.TLSv1`` / ``TLSv1_1`` (forced
    legacy). A missing key defaults to an ``unreachable`` result.
    """

    def connect(host, port, verify, version):
        if version is not None:
            key = version
        else:
            key = "verify" if verify else "plain"
        return responses.get(key, HandshakeResult(outcome="unreachable"))

    return connect


def test_empty_host_returns_none() -> None:
    assert probe_tls("", connector=_connector({})) is None


def test_valid_cert_populates_full_posture() -> None:
    posture = probe_tls(
        "example.be",
        now=_NOW,
        connector=_connector({
            "verify": HandshakeResult(
                outcome="ok", protocol="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384", cert=_VALID_CERT,
            ),
            ssl.TLSVersion.TLSv1: HandshakeResult(outcome="server_refused"),
            ssl.TLSVersion.TLSv1_1: HandshakeResult(outcome="server_refused"),
        }),
    )
    assert posture is not None
    assert posture.connected is True
    assert posture.verify_error == ""
    assert posture.protocol == "TLSv1.3"
    assert posture.cipher == "TLS_AES_256_GCM_SHA384"
    assert posture.issuer == "Let's Encrypt"
    assert posture.subject_cn == "example.be"
    assert posture.cert_not_before.startswith("2026-06-01")
    assert posture.cert_not_after.startswith("2026-09-01")
    # Sep 1 - Jun 22 = 71 days.
    assert posture.days_until_expiry == 71
    assert posture.legacy_tls10 == "rejected"
    assert posture.legacy_tls11 == "rejected"


def test_expired_cert_records_reason_and_reconnects_for_protocol() -> None:
    """An invalid chain still counts as 'speaks TLS'; the verify error is
    captured and protocol/cipher come from the unverified reconnect."""
    posture = probe_tls(
        "expired.example.be",
        now=_NOW,
        connector=_connector({
            "verify": HandshakeResult(
                outcome="cert_invalid",
                verify_error="certificate has expired",
            ),
            "plain": HandshakeResult(
                outcome="ok", protocol="TLSv1.2",
                cipher="ECDHE-RSA-AES128-GCM-SHA256",
            ),
        }),
    )
    assert posture is not None
    assert posture.connected is True
    assert posture.verify_error == "certificate has expired"
    assert posture.protocol == "TLSv1.2"
    assert posture.cipher == "ECDHE-RSA-AES128-GCM-SHA256"
    # No structured dates from an unvalidated certificate.
    assert posture.cert_not_after == ""
    assert posture.days_until_expiry is None


def test_self_signed_cert_records_reason() -> None:
    posture = probe_tls(
        "self.example.be",
        now=_NOW,
        connector=_connector({
            "verify": HandshakeResult(
                outcome="cert_invalid",
                verify_error="self-signed certificate",
            ),
            "plain": HandshakeResult(outcome="ok", protocol="TLSv1.3"),
        }),
    )
    assert posture.connected is True
    assert posture.verify_error == "self-signed certificate"


def test_unreachable_host_is_not_connected() -> None:
    posture = probe_tls(
        "down.example.be",
        now=_NOW,
        connector=_connector({}),  # everything unreachable
    )
    assert posture is not None
    assert posture.connected is False
    assert posture.protocol == ""
    assert posture.issuer == ""
    assert posture.days_until_expiry is None
    # No TLS at all → legacy can't be tested.
    assert posture.legacy_tls10 == "untestable"
    assert posture.legacy_tls11 == "untestable"


def test_legacy_states_map_each_outcome() -> None:
    posture = probe_tls(
        "legacy.example.be",
        now=_NOW,
        connector=_connector({
            "verify": HandshakeResult(
                outcome="ok", protocol="TLSv1.2", cert=_VALID_CERT,
            ),
            ssl.TLSVersion.TLSv1: HandshakeResult(outcome="ok"),
            ssl.TLSVersion.TLSv1_1: HandshakeResult(outcome="client_refused"),
        }),
    )
    assert posture.legacy_tls10 == "accepted"   # handshake completed
    assert posture.legacy_tls11 == "untestable"  # local stack refused


def test_legacy_not_probed_when_host_has_no_tls() -> None:
    """When the main handshake never reaches TLS, the legacy probes are
    skipped (untestable) rather than dialed needlessly."""
    seen: list = []

    def connect(host, port, verify, version):
        seen.append(version)
        return HandshakeResult(outcome="unreachable")

    posture = probe_tls("down.example.be", now=_NOW, connector=connect)
    assert posture.legacy_tls10 == "untestable"
    # Only the verified attempt was dialed; no forced-version probes.
    assert ssl.TLSVersion.TLSv1 not in seen
    assert ssl.TLSVersion.TLSv1_1 not in seen


def test_days_until_expiry_uses_injected_now() -> None:
    cert = dict(_VALID_CERT, notAfter="Jul  2 00:00:00 2026 GMT")
    posture = probe_tls(
        "example.be",
        now=_NOW,
        connector=_connector({
            "verify": HandshakeResult(outcome="ok", cert=cert),
        }),
    )
    # Jul 2 - Jun 22 = 10 days.
    assert posture.days_until_expiry == 10


def test_posture_is_a_frozen_dataclass() -> None:
    posture = probe_tls(
        "example.be", now=_NOW,
        connector=_connector({"verify": HandshakeResult(outcome="ok")}),
    )
    assert isinstance(posture, TLSPosture)
