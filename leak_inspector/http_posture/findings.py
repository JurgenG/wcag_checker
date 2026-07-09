"""Risk-classification rules over :class:`TransportPosture`.

Encodes the operator's stated risk hierarchy:

* **HIGH** — HTTPS doesn't work on the primary host. The site can't
  be reached over TLS — credentials, sessions, cookies all travel
  unencrypted (or the site is broken outright).
* **MEDIUM** — HTTP serves content without redirecting to HTTPS. A
  visitor who types the URL without ``https://`` lands on the
  cleartext version and stays there.
* **LOW (mention)** — HTTP isn't served at all. Worth noting (HSTS
  preloaded site? aggressive HTTPS-only?) but not a risk.
* **MEDIUM** — Only one of (apex, www) resolves. A visitor mistyping
  the other variant gets nothing back.
* **LOW (mention)** — Both apex and www serve content independently
  (neither redirects to the other). SEO and link-equity loss, plus
  the cookie-domain ambiguity is mildly confusing.

When the primary host doesn't respond at all on either scheme, only
the HIGH "HTTPS broken" finding fires — piling on "HTTP doesn't
redirect" / "HTTP absent" on top of that would be noise.
"""

from __future__ import annotations

from dataclasses import dataclass

from .probe import HostProbe, TransportPosture


@dataclass(frozen=True)
class TransportFinding:
    """One transport-posture finding, sized for the executive summary.

    Mirrors the field shape of the existing executive-summary findings
    so the report layer can fold it in without translation.
    """

    severity: str    # "high" | "medium" | "low"
    headline: str    # short one-line label
    detail: str      # one-paragraph explanation


def derive_findings(posture: TransportPosture | None) -> list[TransportFinding]:
    """Apply the risk-classification rules to a posture."""
    if posture is None:
        return []
    findings: list[TransportFinding] = []
    findings.extend(_https_hygiene_findings(posture.primary))
    findings.extend(_canonicalisation_findings(
        posture.primary, posture.alternate,
    ))
    return findings


# ---------------------------------------------------------------------------
# Per-rule derivations
# ---------------------------------------------------------------------------


def _https_hygiene_findings(primary: HostProbe) -> list[TransportFinding]:
    """HIGH if HTTPS broken; MEDIUM if HTTP doesn't redirect; LOW if HTTP absent."""
    # HIGH — primary host has no working HTTPS. Whether HTTP works or
    # not, the site is unreachable over TLS.
    if not primary.https_responded:
        return [TransportFinding(
            severity="high",
            headline=f"HTTPS not available on {primary.host}",
            detail=(
                f"The host {primary.host} did not respond over HTTPS. "
                "Visitors cannot reach this site over an encrypted "
                "connection — credentials, sessions, and cookies travel "
                "unencrypted (or the site is unreachable outright)."
            ),
        )]
    # HTTPS works. Now classify the HTTP side.
    if not primary.http_responded:
        # HTTPS-only — noteworthy but not a risk.
        return [TransportFinding(
            severity="low",
            headline=f"HTTP not served on {primary.host} (HTTPS-only)",
            detail=(
                f"The host {primary.host} accepts HTTPS but not HTTP. "
                "Aggressive HTTPS-only posture; some link previews and "
                "old bookmarks may break, but no security risk."
            ),
        )]
    # Both schemes respond — check whether HTTP redirects to HTTPS.
    if not primary.http_redirects_to_https:
        return [TransportFinding(
            severity="medium",
            headline=f"HTTP on {primary.host} does not redirect to HTTPS",
            detail=(
                f"Browsing {primary.host} over HTTP serves the site "
                "directly instead of redirecting to the HTTPS variant. "
                "A visitor who types the URL without ``https://`` will "
                "transact over an unencrypted connection."
            ),
        )]
    return []  # HTTP → HTTPS redirect configured. Ideal.


def _canonicalisation_findings(
    primary: HostProbe, alternate: HostProbe | None,
) -> list[TransportFinding]:
    """Apex / www canonicalisation rules. No-op when alternate is None
    (subdomain site — apex/www distinction doesn't apply)."""
    if alternate is None:
        return []

    primary_resolves = primary.resolves
    alternate_resolves = alternate.resolves

    # MEDIUM — only one of (apex, www) resolves.
    if primary_resolves and not alternate_resolves:
        return [TransportFinding(
            severity="medium",
            headline=f"{alternate.host} does not resolve (only {primary.host} works)",
            detail=(
                f"Visitors who type {alternate.host} reach nothing. "
                "Set up a 301 redirect on the missing variant so the "
                "domain is reachable at both apex and www."
            ),
        )]
    if alternate_resolves and not primary_resolves:
        # Shouldn't usually happen — primary is the captured host, so
        # it resolved during capture. Guarded for completeness.
        return [TransportFinding(
            severity="medium",
            headline=f"{primary.host} does not resolve (only {alternate.host} works)",
            detail=(
                f"The captured host {primary.host} is currently "
                f"unreachable, while {alternate.host} is working. "
                "Both variants should resolve to the site."
            ),
        )]

    # Both resolve. Check if either redirects to the other.
    if primary_resolves and alternate_resolves:
        if _final_url_targets(alternate, primary.host) or \
           _final_url_targets(primary, alternate.host):
            return []  # One redirects to the other. Ideal.
        # Both serve content independently — LOW mention.
        return [TransportFinding(
            severity="low",
            headline=(
                f"Both {primary.host} and {alternate.host} "
                "serve content independently"
            ),
            detail=(
                "Neither apex nor www redirects to the other; both "
                "respond with their own content. SEO link-equity is "
                "split and cookies set on one variant don't apply to "
                "the other. Pick one as canonical and 301-redirect "
                "the other to it."
            ),
        )]
    return []


def _final_url_targets(probe: HostProbe, target_host: str) -> bool:
    """``True`` if ``probe``'s redirect chains land on ``target_host``."""
    for url in (probe.http_final_url, probe.https_final_url):
        if not url:
            continue
        from urllib.parse import urlparse
        final_host = urlparse(url).hostname or ""
        if final_host == target_host:
            return True
    return False


# ---------------------------------------------------------------------------
# TLS-quality findings
# ---------------------------------------------------------------------------

#: Below this many days a still-valid certificate is "expiring soon" —
#: a resilience (imminent-outage) mention, not a confidentiality break.
CERT_EXPIRY_WARN_DAYS = 14


def derive_tls_findings(tls) -> list[TransportFinding]:
    """Classify a :class:`~leak_inspector.http_posture.tls.TLSPosture`.

    * **HIGH** — the certificate chain failed to validate (expired,
      self-signed, untrusted CA, hostname mismatch): TLS is present but
      unauthenticated, so the connection is MITM-able and browsers show
      an interstitial.
    * **MEDIUM** — a deprecated protocol (TLS 1.0 / 1.1) is *accepted*
      (the confirmed ``"accepted"`` state only; ``"rejected"`` and
      ``"untestable"`` never fire — the certain-data rule).
    * **LOW** — a still-valid certificate expires within
      :data:`CERT_EXPIRY_WARN_DAYS` days (imminent-outage mention).

    A host that did not complete a TLS handshake produces no finding
    here — that is already the transport layer's HTTPS-broken HIGH.
    """
    if tls is None or not tls.connected:
        return []

    if tls.verify_error:
        # Invalid chain dominates: a single HIGH, no expiry double-count.
        return [TransportFinding(
            severity="high",
            headline=f"TLS certificate does not validate on {tls.host}",
            detail=(
                f"The certificate served by {tls.host} failed validation: "
                f"{tls.verify_error}. The connection is encrypted but not "
                "authenticated — it can be intercepted, and browsers show a "
                "security warning."
            ),
        )]

    findings: list[TransportFinding] = []
    accepted = [
        version for version, state in (
            ("1.0", tls.legacy_tls10), ("1.1", tls.legacy_tls11),
        ) if state == "accepted"
    ]
    if accepted:
        versions = "/".join(accepted)
        findings.append(TransportFinding(
            severity="medium",
            headline=f"Deprecated TLS {versions} accepted on {tls.host}",
            detail=(
                f"The host {tls.host} still negotiates TLS {versions}, "
                "a deprecated protocol with known weaknesses (BEAST / POODLE "
                "era). Disable everything below TLS 1.2."
            ),
        ))
    if tls.days_until_expiry is not None \
            and 0 <= tls.days_until_expiry <= CERT_EXPIRY_WARN_DAYS:
        findings.append(TransportFinding(
            severity="low",
            headline=f"TLS certificate for {tls.host} expires soon",
            detail=(
                f"The certificate expires in {tls.days_until_expiry} days. "
                "Confirm automated renewal is working to avoid an outage."
            ),
        ))
    return findings


__all__ = [
    "CERT_EXPIRY_WARN_DAYS",
    "TransportFinding",
    "derive_findings",
    "derive_tls_findings",
]
