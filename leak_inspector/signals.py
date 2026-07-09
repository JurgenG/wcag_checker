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

"""Non-module signal impact ratings (Scoring-v2 Phase 4).

Everything that costs points in the v2 model but is **not** a tracker
module — the missing-hardening posture checks, the cookie/consent
signals, US-ownership of mail/hosting, an end-of-life platform, missing
Subresource Integrity, an absent ``security.txt`` — carries its own
:class:`~leak_inspector.impact.ImpactRating` here, on the same
33-criteria rubric the modules use (``docs/SCORING.md``,
decision 2: *one vocabulary for everything that costs points*).

Each signal is the **adverse** fact (the check *failing*, the header
*missing*, the cookie *present*) and rates the cost of that fact on the
domain(s) it touches. Most are single-axis; a few (a missing
``Referrer-Policy`` leaks the URL to third parties *and* weakens
framing) are dual.

This is a declarative catalog, not the wiring: the aggregation engine
(``score_v2``) consumes :class:`~leak_inspector.report.score_v2.Deduction`
rows, and the switchover phase (roadmap Phase 6) maps each analysis
fact to its signal id and decides the **application** semantics —
whether the consent and end-of-life signals apply as the v1 *caps* or
as ordinary deductions, and how signals dedup against the vendor
modules that set the cookies. The numbers here are rubric-honest
estimates; Phase-6 calibration against the real corpus may rescale
them (exactly as the consent caps were calibrated in v1).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .impact import ImpactRating, register_signal_rating, signal_ratings


@dataclass(frozen=True)
class SignalRating:
    """One non-module signal: its id, label, triple, justification, and
    the report-facing per-domain explainers.

    ``note`` is the internal rubric justification; ``explainers`` maps a
    domain (``"privacy"`` / ``"security"`` / ``"resilience"``) to the
    short string the report shows for that penalty. One is required per
    domain whose rating exceeds 1.0.
    """

    signal_id: str
    label: str
    rating: ImpactRating
    note: str
    explainers: dict[str, str] = field(default_factory=dict)


def _s(signal_id: str, label: str, note: str,
       *, privacy: float = 0.0, security: float = 0.0,
       resilience: float = 0.0,
       explain: dict[str, str] | None = None) -> SignalRating:
    return SignalRating(
        signal_id=signal_id, label=label, note=note,
        rating=ImpactRating(
            privacy=privacy, security=security, resilience=resilience,
        ),
        explainers=explain or {},
    )


#: The catalog, declared as data. Keyed by signal id.
_CATALOG: tuple[SignalRating, ...] = (
    # --- Security posture: the 11 v1 checks, as their failing form ------
    _s("https_broken", "HTTPS not working", security=3.0,
       note="No working transport encryption on the primary host — "
            "severe (rubric security: high attack surface). Rare, so a "
            "large but bounded deduction.",
       explain={"security": "No working HTTPS — traffic can be read or "
                "altered in transit by anyone on the network path."}),
    _s("no_https_redirect", "HTTP not redirected to HTTPS", security=0.5,
       note="HTTP reachable without an upgrade — a downgrade/MITM "
            "opening; modest hardening gap."),
    _s("hsts_missing", "HSTS header absent", security=0.5,
       note="No Strict-Transport-Security — first-visit downgrade "
            "window; modest hardening gap."),
    _s("csp_missing", "Content-Security-Policy absent", security=1.0,
       note="No enforcing CSP — the main in-page XSS / injection "
            "mitigation is missing (rubric security: meaningful)."),
    _s("xcto_missing", "X-Content-Type-Options absent", security=0.5,
       note="No nosniff — MIME-sniffing attack opening; minor."),
    _s("xfo_missing", "X-Frame-Options absent", security=0.5,
       note="No framing control — clickjacking opening; minor."),
    _s("referrer_policy_missing", "Referrer-Policy absent or unsafe",
       privacy=0.5, security=0.5,
       note="The full URL leaks to third parties on every outbound "
            "request (privacy) and framing context weakens (security) — "
            "the one dual-axis header."),
    _s("permissions_policy_missing", "Permissions-Policy absent",
       security=0.5,
       note="Powerful browser features unrestricted — minor hardening "
            "gap."),
    _s("dnssec_unsigned", "DNS zone not DNSSEC-signed",
       security=0.5, resilience=0.5,
       note="No DNS-response integrity (security) and the records can be "
            "spoofed/hijacked (resilience) — split across both."),
    _s("dmarc_weak", "DMARC missing or p=none", security=1.0,
       note="Email domain spoofable — no enforced DMARC policy "
            "(rubric security: meaningful back-office exposure)."),
    _s("cookie_hygiene_bad", "Operator cookies lack Secure/SameSite",
       security=0.5,
       note="The operator's own Set-Cookie headers omit Secure / a "
            "SameSite restriction — minor hardening gap."),
    # --- Email + DNS hygiene (NIS2 Art. 21(2)(g)/(h), CCB CyberFundamentals) --
    _s("spf_weak", "SPF missing or pass-all", security=0.5,
       note="No SPF record, or a record ending in +all/?all that authorises "
            "any sender — the domain is trivially spoofable at the envelope "
            "level. Below dmarc_weak (1.0, the enforcement layer SPF feeds); "
            "a minor hardening gap on its own (rubric security)."),
    _s("caa_missing", "No CAA record", security=0.5,
       note="The zone publishes no CAA record, so any public CA may issue a "
            "certificate for the domain — no issuance-authority restriction "
            "to limit mis-issuance (rubric security: minor hardening gap, "
            "the same class as the missing response headers). internet.nl "
            "checks it."),
    _s("mta_sts_missing", "No MTA-STS policy", security=0.5,
       note="The domain receives mail (publishes MX) but advertises no "
            "MTA-STS policy, so inbound SMTP can be downgraded to cleartext "
            "by an on-path attacker — the email-transport equivalent of a "
            "missing HSTS (rubric security: minor hardening gap). Only fires "
            "when an MX exists; a no-mail domain is never penalised."),
    # --- Resilience: DNS redundancy -------------------------------------------
    _s("dns_single_nameserver", "Single authoritative nameserver",
       resilience=0.5,
       note="Only one authoritative nameserver name is published — RFC 2182 "
            "requires at least two. A single name is a resolution "
            "single-point-of-failure (rubric resilience). Fires only on "
            "exactly one NS; zero means the lookup did not resolve and is "
            "never scored (certain-data rule).",
       explain={"resilience": "The domain has only one authoritative "
                "nameserver — if it goes down, the site becomes unreachable "
                "(standards require at least two)."}),
    # --- TLS quality (NIS2 cryptography, CCB CyberFundamentals) ----------
    _s("tls_cert_invalid", "TLS certificate does not validate", security=2.0,
       note="The certificate chain fails validation (expired / self-signed "
            "/ untrusted CA / hostname mismatch) — TLS is present but "
            "unauthenticated, so traffic is MITM-able and browsers warn. "
            "Below https_broken (3.0, no TLS at all), above the minor "
            "header gaps (rubric security: meaningful).",
       explain={"security": "The site's TLS certificate doesn't validate — "
                "the encrypted connection can be intercepted and browsers "
                "show a security warning."}),
    _s("tls_legacy_protocol", "Deprecated TLS 1.0/1.1 accepted", security=1.0,
       note="The host still negotiates a deprecated TLS version (BEAST / "
            "POODLE-era weaknesses) — a NIS2/PCI failure (rubric security: "
            "meaningful). Only a confirmed acceptance fires; an untestable "
            "result never penalises."),
    _s("tls_cert_expiring_soon", "TLS certificate expires within 14 days",
       resilience=0.5,
       note="A still-valid certificate is within two weeks of expiry — an "
            "imminent-outage risk if renewal isn't automated; minor "
            "resilience concern, not a confidentiality break."),
    # --- Security: extras the v1 checklist doesn't score ----------------
    _s("eol_platform", "End-of-life web platform", security=5.0,
       note="The site runs a CMS/platform past end-of-life — unpatched "
            "known-CVE surface (rubric security 5.0). v1 applies this as "
            "a cap-at-5; Phase 6 decides cap-vs-deduction.",
       explain={"security": "The site runs an end-of-life platform that "
                "no longer receives security patches — known "
                "vulnerabilities stay open."}),
    _s("missing_sri_script", "Third-party script without SRI",
       security=1.0,
       note="A third-party <script> with no integrity hash — a CDN "
            "compromise injects code into the origin (rubric security: "
            "supply-chain)."),
    _s("missing_sri_stylesheet", "Third-party stylesheet without SRI",
       security=0.5,
       note="A third-party stylesheet with no integrity hash — "
            "style-capable injection only (lower than a script)."),
    _s("security_txt_missing", "No RFC 9116 security.txt", security=0.5,
       note="No machine-readable security contact — a small posture "
            "gap (OpenKAT / internet.nl both check it)."),
    # --- Resilience: server sovereignty (physical + jurisdiction) -------
    # Scored per infrastructure component (web host, mail, DNS) on two
    # independent axes: where the server physically sits (geoip) and which
    # legal regime its operator answers to (ASN registration country).
    # Jurisdiction outweighs physical location — the CLOUD Act / FISA reach
    # over the operator is the sharper sovereignty exposure than data-at-rest.
    _s("host_physical_extra_eu", "Web host physically outside the EU",
       resilience=2.0,
       note="The site's web host geolocates outside the EU — its data at "
            "rest sits under a non-EU regime.",
       explain={"resilience": "The website is served from a datacentre "
                "physically outside the EU — its data at rest sits under a "
                "non-EU legal regime."}),
    _s("host_jurisdiction_extra_eu", "Web host under non-EU jurisdiction",
       resilience=3.0,
       note="The web host's ASN is registered outside the EU — the "
            "operator can be compelled under a foreign regime (CLOUD Act / "
            "FISA), regardless of where the server physically sits.",
       explain={"resilience": "The website's host is operated by a network "
                "registered outside the EU — it can be compelled to hand "
                "over data under a foreign regime (e.g. the US CLOUD Act)."}),
    _s("mail_physical_extra_eu", "Mail host physically outside the EU",
       resilience=2.0,
       note="The domain's mail (MX) host geolocates outside the EU — "
            "correspondence at rest under a non-EU regime.",
       explain={"resilience": "Inbound mail is handled by a server "
                "physically outside the EU — correspondence at rest sits "
                "under a non-EU legal regime."}),
    _s("mail_jurisdiction_extra_eu", "Mail host under non-EU jurisdiction",
       resilience=3.0,
       note="The mail host's ASN is registered outside the EU — "
            "back-office correspondence under foreign-regime reach.",
       explain={"resilience": "Inbound mail is handled by a network "
                "registered outside the EU — correspondence can be "
                "compelled under a foreign regime (e.g. the US CLOUD Act)."}),
    _s("dns_physical_extra_eu", "DNS host physically outside the EU",
       resilience=2.0,
       note="The domain's authoritative nameservers geolocate outside the "
            "EU — name resolution depends on non-EU infrastructure.",
       explain={"resilience": "The authoritative nameservers sit physically "
                "outside the EU — name resolution depends on non-EU "
                "infrastructure."}),
    _s("dns_jurisdiction_extra_eu", "DNS host under non-EU jurisdiction",
       resilience=3.0,
       note="The nameservers' ASN is registered outside the EU — control "
            "of the zone's resolution under a foreign regime.",
       explain={"resilience": "The authoritative nameservers are operated by "
                "a network registered outside the EU — control of the "
                "domain's resolution sits under a foreign regime."}),
    _s("no_ipv6", "No IPv6 (AAAA) on the primary host", resilience=0.5,
       note="The primary domain publishes no AAAA record — reachable over "
            "legacy IPv4 only. A small infrastructure-modernity / "
            "reachability gap (rubric resilience), not a security or "
            "privacy fault."),
    # --- Privacy: cookies + consent compliance --------------------------
    _s("persistent_xs_cookie", "Persistent cross-site tracking cookie",
       privacy=3.0,
       note="A persistent (>30d) SameSite=None third-party cookie — the "
            "posture consent rules prohibit. v1 caps privacy at 5; "
            "Phase 6 decides cap-vs-deduction and dedup against the "
            "vendor module that set it.",
       explain={"privacy": "A persistent third-party cookie that follows "
                "the visitor across sites — the cross-site tracking "
                "consent rules are meant to prevent."}),
    _s("forwarded_tracking_cookie", "Forwarded first-party tracker cookie",
       privacy=1.0,
       note="A first-party cookie of a cloaking/forwarding vendor — the "
            "identifier still reaches the third party. The forwarding "
            "*module* already deducts 4.5, so Phase 6 must dedup; this is "
            "the corroborating cookie signal."),
    _s("pre_consent_tracking", "Tracking before the consent decision",
       privacy=4.0,
       note="A third-party identifier/PII field shipped before the "
            "visitor decided — unlawful regardless of the eventual "
            "choice. v1 caps privacy at 5; Phase 6 decides "
            "cap-vs-deduction.",
       explain={"privacy": "This vendor received visitor data before the "
                "visitor made any consent choice — data left before "
                "permission was given."}),
    _s("post_reject_tracking", "Tracking after an explicit reject",
       privacy=5.0,
       note="Tracking continued after the visitor said no — the starkest "
            "violation (rubric privacy 5.0). v1 caps privacy at 2; "
            "Phase 6 decides cap-vs-deduction.",
       explain={"privacy": "This vendor kept receiving visitor data after "
                "the visitor explicitly rejected tracking — the starkest "
                "consent violation."}),
)

#: ``signal_id -> SignalRating``. Pure data; mutate nothing on import.
SIGNAL_CATALOG: dict[str, SignalRating] = {s.signal_id: s for s in _CATALOG}


def register_all() -> None:
    """Register every catalog signal into the global signal registry.

    Idempotent — skips ids already present — so it is safe to call from
    multiple entry points and across test runs (the registry raises on a
    genuine duplicate, which would be two *different* owners for one id).
    """
    existing = signal_ratings()
    for signal_id, entry in SIGNAL_CATALOG.items():
        if signal_id not in existing:
            register_signal_rating(signal_id, entry.rating)


# Populate the registry on import so the generated overview and the
# scorer see the non-module signals without a separate bootstrap step.
register_all()


__all__ = ["SIGNAL_CATALOG", "SignalRating", "register_all"]
