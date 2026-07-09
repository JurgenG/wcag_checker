"""Tests for the finding-derivation rules over a :class:`TransportPosture`.

The user-specified risk levels:

* HTTPS broken on primary → HIGH
* HTTP doesn't redirect to HTTPS (both schemes serve) → MEDIUM
* HTTP not served (HTTPS-only) → LOW mention

Apex / www canonicalisation (only when ``alternate`` is set):

* Only one of (apex, www) resolves → MEDIUM
* Both resolve independently (neither redirects to the other) → LOW
* One redirects to the other → no finding (ideal)
"""

from __future__ import annotations

from leak_inspector.http_posture import HostProbe, TransportPosture
from leak_inspector.http_posture.findings import (
    TransportFinding, derive_findings, derive_tls_findings,
)
from leak_inspector.http_posture.tls import TLSPosture


def _hp(
    host: str,
    *,
    http: bool = True, https: bool = True,
    http_status: int | None = 200, https_status: int | None = 200,
    http_final: str | None = None, https_final: str | None = None,
) -> HostProbe:
    """Build a HostProbe with sensible defaults for findings tests."""
    return HostProbe(
        host=host,
        http_responded=http, https_responded=https,
        http_status=http_status if http else None,
        https_status=https_status if https else None,
        http_final_url=http_final if http else None,
        https_final_url=https_final if https else None,
    )


def _severities(findings: list[TransportFinding]) -> list[str]:
    return [f.severity for f in findings]


def _headlines(findings: list[TransportFinding]) -> list[str]:
    return [f.headline for f in findings]


# --- HTTPS hygiene findings ------------------------------------------------


def test_high_finding_when_https_broken_on_primary() -> None:
    posture = TransportPosture(
        primary=_hp("example.be", https=False, http=True,
                    http_final="http://example.be/"),
        alternate=None,
    )
    findings = derive_findings(posture)
    assert "high" in _severities(findings)
    assert any("HTTPS" in h for h in _headlines(findings))


def test_medium_finding_when_http_does_not_redirect_to_https() -> None:
    """Both HTTP and HTTPS work, but HTTP serves its own content
    (final URL is still HTTP) → MEDIUM."""
    posture = TransportPosture(
        primary=_hp(
            "example.be",
            http_final="http://example.be/",   # serves itself, no upgrade
            https_final="https://example.be/",
        ),
        alternate=None,
    )
    findings = derive_findings(posture)
    assert "medium" in _severities(findings)
    assert any("redirect" in h.lower() for h in _headlines(findings))


def test_low_mention_when_http_is_absent() -> None:
    """HTTPS-only site. The HTTP scheme not being served is worth
    mentioning but not risk-inducing."""
    posture = TransportPosture(
        primary=_hp("example.be", http=False, https=True,
                    https_final="https://example.be/"),
        alternate=None,
    )
    findings = derive_findings(posture)
    assert "low" in _severities(findings)
    assert any("HTTP" in h for h in _headlines(findings))


def test_no_finding_when_http_redirects_to_https() -> None:
    """The ideal case: HTTP serves a 301 to HTTPS, HTTPS serves the site."""
    posture = TransportPosture(
        primary=_hp(
            "example.be",
            http_final="https://example.be/",  # HTTP upgrades to HTTPS
            https_final="https://example.be/",
        ),
        alternate=None,
    )
    findings = derive_findings(posture)
    # No HTTPS-hygiene findings. (Apex/www has no alternate so no findings there.)
    assert findings == []


# --- Apex / www canonicalisation -------------------------------------------


def test_medium_finding_when_only_one_of_apex_or_www_resolves() -> None:
    posture = TransportPosture(
        primary=_hp(
            "example.be",
            http_final="https://example.be/",
            https_final="https://example.be/",
        ),
        alternate=HostProbe(
            host="www.example.be",
            http_responded=False, https_responded=False,
            http_status=None, https_status=None,
            http_final_url=None, https_final_url=None,
        ),
    )
    findings = derive_findings(posture)
    assert "medium" in _severities(findings)
    assert any("www" in h.lower() or "apex" in h.lower()
               for h in _headlines(findings))


def test_low_mention_when_both_apex_and_www_serve_independently() -> None:
    """Neither redirects to the other — they both serve content on their
    own host. Mention but not risk-inducing."""
    posture = TransportPosture(
        primary=_hp(
            "example.be",
            http_final="https://example.be/",
            https_final="https://example.be/",
        ),
        alternate=_hp(
            "www.example.be",
            http_final="https://www.example.be/",
            https_final="https://www.example.be/",
        ),
    )
    findings = derive_findings(posture)
    severities = _severities(findings)
    # The HTTPS hygiene is perfect, so the only finding should be the
    # LOW canonicalisation mention.
    assert "high" not in severities
    assert "medium" not in severities
    assert "low" in severities


def test_no_finding_when_one_variant_redirects_to_the_other() -> None:
    """The ideal apex/www case: www → apex (or apex → www) via 301."""
    posture = TransportPosture(
        primary=_hp(
            "example.be",
            http_final="https://example.be/",
            https_final="https://example.be/",
        ),
        alternate=_hp(
            "www.example.be",
            # www variant redirects to apex on both schemes
            http_final="https://example.be/",
            https_final="https://example.be/",
        ),
    )
    findings = derive_findings(posture)
    assert findings == []


# --- Edge cases ------------------------------------------------------------


def test_no_findings_when_posture_is_none() -> None:
    assert derive_findings(None) == []


def test_no_findings_when_primary_is_fully_unreachable() -> None:
    """If the primary host doesn't respond at all, the HTTPS-broken
    finding fires (HIGH) — but we don't pile on "no redirect" /
    "HTTP absent" on top of it."""
    posture = TransportPosture(
        primary=HostProbe(
            host="example.be",
            http_responded=False, https_responded=False,
            http_status=None, https_status=None,
            http_final_url=None, https_final_url=None,
        ),
        alternate=None,
    )
    findings = derive_findings(posture)
    # Exactly one HIGH finding — don't double-fire.
    severities = _severities(findings)
    assert severities == ["high"]


# --- TLS-quality findings --------------------------------------------------


def _tls(**kw) -> TLSPosture:
    base = dict(
        host="example.be", connected=True, protocol="TLSv1.3",
        verify_error="", days_until_expiry=90,
        legacy_tls10="rejected", legacy_tls11="rejected",
    )
    base.update(kw)
    return TLSPosture(**base)


def test_no_tls_findings_when_posture_is_none() -> None:
    assert derive_tls_findings(None) == []


def test_no_tls_findings_for_a_clean_posture() -> None:
    assert derive_tls_findings(_tls()) == []


def test_no_tls_findings_when_host_has_no_tls() -> None:
    """An unreachable TLS endpoint is already covered by the transport
    HTTPS-broken finding — don't double-report it here."""
    assert derive_tls_findings(_tls(connected=False)) == []


def test_high_finding_when_certificate_is_invalid() -> None:
    findings = derive_tls_findings(_tls(verify_error="certificate has expired"))
    assert _severities(findings) == ["high"]
    assert any("certificate" in h.lower() for h in _headlines(findings))


def test_medium_finding_when_legacy_tls_accepted() -> None:
    findings = derive_tls_findings(_tls(legacy_tls10="accepted"))
    assert "medium" in _severities(findings)
    assert any("1.0" in h or "1.1" in h or "TLS" in h for h in _headlines(findings))


def test_legacy_rejected_or_untestable_does_not_fire() -> None:
    assert derive_tls_findings(_tls(legacy_tls10="untestable")) == []
    assert derive_tls_findings(_tls(legacy_tls11="rejected")) == []


def test_low_finding_when_certificate_expiring_soon() -> None:
    findings = derive_tls_findings(_tls(days_until_expiry=7))
    assert _severities(findings) == ["low"]
    assert any("expir" in h.lower() for h in _headlines(findings))


def test_expiring_soon_does_not_fire_on_invalid_cert() -> None:
    """An invalid chain is already a HIGH finding; don't also count
    'expiring soon' (would be a double-penalty for the same cert)."""
    findings = derive_tls_findings(
        _tls(verify_error="certificate has expired", days_until_expiry=-1)
    )
    assert _severities(findings) == ["high"]
