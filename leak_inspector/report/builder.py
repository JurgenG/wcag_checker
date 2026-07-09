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

"""Build a :class:`~.document.ReportDocument` from an :class:`~..analysis.Analysis`.

This is the single derivation step in the reporting pipeline. Every
renderer downstream consumes the document; none of them re-derive
from the raw :class:`Analysis`.

The builder absorbs the heuristics that used to live as scattered
helpers inside :mod:`.text` — finding heuristics, vendor-rollup
canonicalisation, country-flag mapping, jurisdiction tallies,
per-tracker drill-down construction.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Iterable

import tldextract

from ..analysis import Analysis
from ..dns_posture import DNSPosture
from ..modules.base import (
    CAT_HTTP_TRAFFIC,
    CAT_IDENTIFIER,
    CAT_PII,
    CATEGORIES,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
)
from .debug import collect_unknown_hosts
from .document import (
    SCHEMA_VERSION,
    CategoryGroup,
    CloakRecord,
    ExecutiveSummary,
    FieldRef,
    Finding,
    HarvestedField,
    JurisdictionTally,
    ManifestView,
    ModuleRef,
    ModuleSection,
    ParamRow,
    RepresentativeHit,
    ReportDocument,
    SampleUrl,
    SummaryStats,
    TopByImpactEntry,
    UnclassifiedHost,
    VendorMeta,
    VendorRollup,
)


# ---------------------------------------------------------------------------
# Constants — heuristic inputs lifted from text.py
# ---------------------------------------------------------------------------

#: Modules whose presence implies the operator records full visitor
#: interaction (mouse / clicks / scroll / DOM mutations / form input).
SESSION_REPLAY_MODULES: frozenset[str] = frozenset({
    "clarity", "hotjar", "fullstory",
})

#: Modules that ship visitor-submitted form values to a vendor backend.
FORM_DATA_MODULES: frozenset[str] = frozenset({
    "hubspot", "mailchimp", "mailjet",
})

#: Jurisdictions that materially raise transfer-risk under GDPR Schrems
#: II / comparable EU-side frameworks.
HIGH_RISK_JURISDICTIONS: frozenset[str] = frozenset({"US", "CN", "RU"})

#: EU member states as of 2026 (UK departed in 2020). Used to override
#: the per-country flag with the EU flag in jurisdiction badges.
EU_MEMBERS: frozenset[str] = frozenset({
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE",
})

#: One-sentence explanation per parameter category — feeds the HTML
#: category-label tooltip.
CATEGORY_DESCRIPTIONS: dict[str, str] = {
    CAT_PII: (
        "Personally Identifiable Information — direct or hashed user-level data "
        "(email, phone, name, postal, client IP)."
    ),
    CAT_IDENTIFIER: (
        "Persistent or per-event identifiers — visitor pseudonyms, session IDs, "
        "ad cookie values, cross-vendor sync tokens. Enable linkability across "
        "requests and (when persistent) across sessions."
    ),
    "behavioral": (
        "User-action data — events, ecommerce values, engagement timing, "
        "experiment assignments. Describes what the visitor did on the site."
    ),
    "content": (
        "Page URL, document title, referrer, embedded text. Reveals which "
        "content the visitor was viewing when each event fired."
    ),
    "technical": (
        "Environment and fingerprint surface — screen / viewport dimensions, "
        "language, timezone, plugin probes, SDK version. Browser-identifying "
        "but not directly user-identifying."
    ),
    "consent": (
        "Consent-state signals — IAB TCF strings, Global Privacy Platform "
        "(GPP), Google consent mode, anonymize-IP / non-personalized-ads flags."
    ),
    CAT_HTTP_TRAFFIC: (
        "Ambient HTTP-layer metadata — visitor IP, Referer, Cookie, User-Agent, "
        "Client Hints. Disclosed by virtue of the connection itself, before any "
        "payload-level tracking."
    ),
    "other": (
        "Unrecognized or unclassified parameters — value visible in the report, "
        "meaning not documented for this tracker."
    ),
}

#: Canned tooltip surfaced on every CNAME-cloak row in HTML.
CNAME_CLOAK_TOOLTIP = (
    "CNAME cloaking — a first-party-looking subdomain DNS-resolves via a "
    "CNAME record to a third-party tracker. The HTTP Host header, TLS SNI, "
    "JavaScript origin, and cookie scope all see the alias as first-party, "
    "bypassing tracker-protection lists and third-party-cookie restrictions."
)

#: Emoji severity badge used in every renderer. Index by impact constant.
SEVERITY_BADGES: dict[str, str] = {
    IMPACT_HIGH:   "🔴",
    IMPACT_MEDIUM: "🟡",
    IMPACT_LOW:    "🟢",
}


# ---------------------------------------------------------------------------
# Small helpers — pure functions used by the builder
# ---------------------------------------------------------------------------


def _registrable(url_or_host: str) -> str:
    """Return the registrable (eTLD+1) domain for a URL or bare host."""
    ext = tldextract.extract(url_or_host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p)


def _country_flag(jurisdiction: str) -> tuple[str, bool]:
    """Return ``(flag_emoji, is_eu_member)`` for a 2-letter jurisdiction code.

    EU member states return the EU flag — the report emphasizes the
    *legal framework*, not the individual member. UK gets the GB flag
    (commonly written as the non-ISO ``UK``).
    """
    code = (jurisdiction or "").strip().upper()
    if code in EU_MEMBERS or code == "EU":
        return ("🇪🇺", True)
    if code == "UK":
        return ("🇬🇧", False)
    if len(code) == 2 and code.isalpha():
        flag = (
            chr(0x1F1E6 + ord(code[0]) - ord("A"))
            + chr(0x1F1E6 + ord(code[1]) - ord("A"))
        )
        return (flag, False)
    return ("", False)


def _canonical_key(key: str) -> str:
    """Strip ``(body) `` / ``(path) `` / ``(body ev#N) `` prefixes."""
    if key.startswith("(body) "):
        return key[7:]
    if key.startswith("(path) "):
        return key[7:]
    if key.startswith("(body ev#"):
        idx = key.find(") ", 9)
        if idx > 0:
            return key[idx + 2:]
    return key


def _build_vendor_tooltip(meta: TrackerModule | None) -> str:
    """Compose the vendor sovereignty tooltip from module metadata."""
    if meta is None:
        return ""
    parts: list[str] = []
    if meta.vendor:
        parts.append(meta.vendor)
    if meta.legal_jurisdiction:
        parts.append(f"jurisdiction: {meta.legal_jurisdiction}")
    if meta.data_residency:
        parts.append(f"residency: {meta.data_residency}")
    if meta.sovereignty_notes:
        parts.append(meta.sovereignty_notes)
    return " · ".join(parts)


def _vendor_label(meta: TrackerModule | None, fallback: str) -> str:
    """Canonical vendor label — strips trailing parenthetical disambiguation.

    A module's ``rollup_label`` opts out of the strip and gets its own
    bucket in the executive-summary vendor rollup. Used by modules that
    represent a deployment pattern distinct from their parent vendor's
    other products (Google Tag First-Party Mode is the canonical case).
    """
    if meta is not None and getattr(meta, "rollup_label", ""):
        return meta.rollup_label
    raw = meta.vendor if (meta and meta.vendor) else fallback
    return raw.split(" (")[0].strip() or fallback


def _jurisdiction_background_class(code: str) -> str:
    """Return the renderer-hint class for a jurisdiction badge.

    Mirrors the existing CSS color buckets — high-risk for Schrems II
    triggers, "eu" for GDPR-bound, "uk" as a separate post-Brexit
    regime, "other-western" for the rest.
    """
    code = (code or "").upper()
    if code in HIGH_RISK_JURISDICTIONS:
        return "high-risk"
    if code in EU_MEMBERS or code == "EU":
        return "eu"
    if code == "UK":
        return "uk"
    if code in {"NZ", "AU", "JP", "CH", "NO"}:
        return "other-western"
    return ""


# ---------------------------------------------------------------------------
# Executive summary builders
# ---------------------------------------------------------------------------


def _build_cname_cloaks(analysis: Analysis) -> list[CloakRecord]:
    """Extract every distinct ``(cname-cloak)`` attribution from the hits."""
    seen: set[str] = set()
    out: list[CloakRecord] = []
    for hit in analysis.hits:
        if hit.host in seen:
            continue
        for param in hit.params:
            if param.key == "(cname-cloak) canonical":
                value = str(param.value)
                if "→" in value:
                    _, _, tail = value.partition("→")
                    canonical = tail.strip()
                else:
                    canonical = value.strip()
                out.append(CloakRecord(
                    alias=hit.host,
                    canonical=canonical,
                    vendor_module_name=hit.module_name,
                    module_id=hit.module_id,
                ))
                seen.add(hit.host)
                break
    return out


def _build_high_impact_by_vendor(
    analysis: Analysis,
    meta_by_id: dict[str, TrackerModule],
) -> list[VendorRollup]:
    """Roll up HIGH-impact ParamInfos by canonicalized vendor.

    Skips the ambient ``(http) X`` rows (which are universal) and the
    ``(cname-cloak) …`` row (already surfaced in its own block) so the
    rollup describes vendor-specific tracking.
    """
    # vendor_label → {category: {key: (count, meaning)}, "_modules": set}
    accum: dict[str, dict] = {}
    for hit in analysis.hits:
        meta = meta_by_id.get(hit.module_id)
        vendor_label = _vendor_label(meta, hit.module_name)
        for param in hit.params:
            if param.privacy_impact != IMPACT_HIGH:
                continue
            if param.key.startswith("(http) "):
                continue
            if param.key.startswith("(cname-cloak) "):
                continue
            entry = accum.setdefault(vendor_label, {"_modules": set(), "_by_cat": {}})
            entry["_modules"].add(hit.module_name)
            key = _canonical_key(param.key)
            cat_entries = entry["_by_cat"].setdefault(param.category, {})
            if key not in cat_entries:
                cat_entries[key] = {"count": 0, "meaning": param.meaning or ""}
            cat_entries[key]["count"] += 1

    # Build the per-module-name → meta reverse lookup so we can attach
    # per-module tooltips inside each vendor's bracket.
    meta_by_module_name = {m.module_name: m for m in meta_by_id.values()}

    out: list[VendorRollup] = []
    for vendor_label, data in accum.items():
        modules = sorted(data["_modules"])
        module_refs = [
            ModuleRef(
                name=name,
                tooltip=_build_vendor_tooltip(meta_by_module_name.get(name)),
            )
            for name in modules
        ]

        categories: list[CategoryGroup] = []
        total = 0
        for category in CATEGORIES:
            cat_entries = data["_by_cat"].get(category)
            if not cat_entries:
                continue
            ordered = sorted(
                cat_entries.items(), key=lambda kv: (-kv[1]["count"], kv[0])
            )
            fields = [FieldRef(key=k, meaning=v["meaning"]) for k, v in ordered]
            total += len(fields)
            categories.append(CategoryGroup(
                category=category,
                description=CATEGORY_DESCRIPTIONS.get(category, ""),
                fields=fields,
            ))

        # Vendor-level tooltip uses any module's meta (they all share
        # the canonicalized vendor name).
        vendor_meta = next(
            (
                meta_by_module_name.get(n)
                for n in modules
                if meta_by_module_name.get(n) is not None
            ),
            None,
        )
        out.append(VendorRollup(
            vendor_label=vendor_label,
            vendor_tooltip=_build_vendor_tooltip(vendor_meta),
            modules=module_refs,
            categories=categories,
            total_high_impact_fields=total,
        ))
    out.sort(key=lambda r: -r.total_high_impact_fields)
    return out


def _build_jurisdictions(
    analysis: Analysis,
    meta_by_id: dict[str, TrackerModule],
) -> list[JurisdictionTally]:
    """Per-jurisdiction module count + deduped vendor sample."""
    counts: Counter[str] = Counter()
    vendors_by_jur: dict[str, list[str]] = {}
    by_module = analysis.hits_by_module()
    for mid in by_module:
        meta = meta_by_id.get(mid)
        if meta is None or not meta.legal_jurisdiction:
            continue
        jur = meta.legal_jurisdiction
        counts[jur] += 1
        short = _vendor_label(meta, by_module[mid][0].module_name)
        bucket = vendors_by_jur.setdefault(jur, [])
        if short not in bucket:
            bucket.append(short)

    out: list[JurisdictionTally] = []
    for jur, count in counts.most_common():
        flag, is_eu = _country_flag(jur)
        out.append(JurisdictionTally(
            code=jur,
            flag=flag,
            is_eu=is_eu,
            module_count=count,
            vendors=vendors_by_jur[jur],
            background_class=_jurisdiction_background_class(jur),
        ))
    return out


def _build_top_by_impact(
    analysis: Analysis, meta_by_id: dict[str, TrackerModule]
) -> list[TopByImpactEntry]:
    """Rank trackers by HIGH-impact param count first, then MEDIUM, then hits.

    Excludes ambient ``(http) X`` rows from the impact counts —
    those don't differentiate trackers (every vendor sees them).
    """
    by_module = analysis.hits_by_module()
    entries: list[TopByImpactEntry] = []
    for mid, hits in by_module.items():
        high = 0
        medium = 0
        for hit in hits:
            for p in hit.params:
                if p.key.startswith("(http) "):
                    continue
                if p.privacy_impact == IMPACT_HIGH:
                    high += 1
                elif p.privacy_impact == IMPACT_MEDIUM:
                    medium += 1
        entries.append(TopByImpactEntry(
            module_id=mid,
            module_name=hits[0].module_name,
            high_impact_field_count=high,
            medium_impact_field_count=medium,
            hit_count=len(hits),
        ))
    entries.sort(
        key=lambda e: (
            -e.high_impact_field_count,
            -e.medium_impact_field_count,
            -e.hit_count,
        )
    )
    return entries[:3]


def _consent_mode_note(signals: tuple[str, ...]) -> str:
    """Corroborating clause from Google Consent Mode ``gcs`` signals.

    ``gcs`` is ``G1`` + ad-storage bit + analytics-storage bit, so
    ``G100`` means both denied. Only when *every* observed signal is
    unambiguously all-denied do we add the corroboration — a mixed or
    granted signal isn't editorialised (certainty rule).
    """
    if signals and all(s.startswith("G1") and set(s[2:]) == {"0"} for s in signals):
        return (
            " Google Consent Mode corroborates this on the wire: every "
            f"beacon reported storage denied ({', '.join(signals)})."
        )
    return ""


def _build_consent_findings(analysis: Analysis) -> list[Finding]:
    """Findings for tracking that defied the visitor's consent choice.

    Two violations, both HIGH: tracking that continued *after* an
    explicit reject, and personal data sent *before* any decision was
    made. Silent when the consent state is unknown (no decodable CMP)
    or when no offending vendor fired — never inferred.
    """
    consent = getattr(analysis, "consent", None)
    if consent is None:
        return []
    findings: list[Finding] = []

    post = consent.post_reject_vendors
    if post:
        detail = (
            f"After the reject: {', '.join(post)}. These shipped "
            "personal data despite an explicit refusal (ePrivacy "
            "Directive / GDPR Art. 6 — no lawful basis)."
        )
        detail += _consent_mode_note(consent.consent_mode_signals)
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                f"Tracking continued after the visitor rejected consent — "
                f"{len(post)} vendor{'s' if len(post) != 1 else ''}"
            ),
            detail=detail,
            action=(
                "Gate these vendors behind the CMP so a reject actually "
                "blocks them; a refused choice must stop processing."
            ),
            kind="consent_post_reject",
        ))

    pre = consent.pre_decision_vendors
    if pre:
        when = (
            "before the visitor made any choice"
            if consent.state == "none"
            else "before the visitor decided"
        )
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                f"{len(pre)} vendor{'s' if len(pre) != 1 else ''} sent personal "
                f"data {when}"
            ),
            detail=(
                f"Fired pre-consent: {', '.join(pre)}. Personal data left the "
                "browser before a lawful basis was established."
            ),
            action=(
                "Hold non-essential tags until the consent signal resolves "
                "(Consent Mode / CMP gating)."
            ),
            kind="consent_pre_decision",
        ))
    return findings


def _build_sri_findings(analysis: Analysis) -> list[Finding]:
    """Finding for third-party subresources without Subresource Integrity.

    Covers ``<script src>`` and ``<link rel=stylesheet>`` references.
    Silent when nothing third-party lacked an ``integrity`` hash (or the
    bundle predates page-source capture). This is a latent supply-chain
    weakness — no data has necessarily leaked — so it is MEDIUM and the
    wording stays informative rather than alarmist.
    """
    missing = getattr(analysis, "missing_sri", None)
    if not missing:
        return []
    hosts = list(dict.fromkeys(m.host for m in missing))  # distinct, ordered
    shown = ", ".join(hosts[:6])
    if len(hosts) > 6:
        shown += f", +{len(hosts) - 6} more"
    n_css = sum(1 for m in missing if getattr(m, "kind", "script") == "stylesheet")
    n_js = len(missing) - n_css
    if n_js and n_css:
        what = (
            f"{n_js} third-party script{'s' if n_js != 1 else ''} and "
            f"{n_css} stylesheet{'s' if n_css != 1 else ''}"
        )
    elif n_css:
        what = f"{n_css} third-party stylesheet{'s' if n_css != 1 else ''}"
    else:
        what = f"{n_js} third-party script{'s' if n_js != 1 else ''}"
    return [Finding(
        severity=IMPACT_MEDIUM,
        badge=SEVERITY_BADGES[IMPACT_MEDIUM],
        headline=f"{what} loaded without Subresource Integrity",
        detail=(
            f"No integrity hash on subresources from {len(hosts)} third-party "
            f"host{'s' if len(hosts) != 1 else ''} ({shown}). If one of these "
            "hosts is compromised, altered code would execute in the site's "
            "own origin — a supply-chain vector for injecting trackers."
        ),
        action=(
            "Add an SRI integrity hash (with crossorigin) to third-party "
            "<script> and stylesheet <link> tags, or self-host the asset."
        ),
        kind="sri_missing",
    )]


def _build_sri_protected_findings(analysis: Analysis) -> list[Finding]:
    """Positive finding: third-party subresources pinned with an SRI hash.

    The counterpart to :func:`_build_sri_findings`. When the operator has
    pinned a third-party ``<script src>`` / ``<link rel=stylesheet>`` with
    an ``integrity`` hash, a compromised CDN cannot swap in attacker code —
    a security positive worth surfacing as a green LOW finding (no action),
    mirroring the DNSSEC-signed positive. Silent when nothing third-party
    carried a hash. Coexists with the missing-SRI finding on a mixed page.
    """
    protected = getattr(analysis, "protected_sri", None)
    if not protected:
        return []
    hosts = list(dict.fromkeys(p.host for p in protected))  # distinct, ordered
    shown = ", ".join(hosts[:6])
    if len(hosts) > 6:
        shown += f", +{len(hosts) - 6} more"
    n_css = sum(1 for p in protected if getattr(p, "kind", "script") == "stylesheet")
    n_js = len(protected) - n_css
    if n_js and n_css:
        what = (
            f"{n_js} third-party script{'s' if n_js != 1 else ''} and "
            f"{n_css} stylesheet{'s' if n_css != 1 else ''}"
        )
    elif n_css:
        what = f"{n_css} third-party stylesheet{'s' if n_css != 1 else ''}"
    else:
        what = f"{n_js} third-party script{'s' if n_js != 1 else ''}"
    return [Finding(
        severity=IMPACT_LOW,
        badge=SEVERITY_BADGES[IMPACT_LOW],
        headline=f"{what} protected with Subresource Integrity",
        detail=(
            f"An integrity hash pins the body of subresources from "
            f"{len(hosts)} third-party host{'s' if len(hosts) != 1 else ''} "
            f"({shown}). If one of these hosts is compromised, the browser "
            "refuses the altered body — closing that supply-chain vector."
        ),
        kind="sri_protected",
    )]


def _build_first_party_tracking_cookie_findings(
    analysis: Analysis,
) -> list[Finding]:
    """Informational finding for first-party JS-set tracking cookies.

    Names the recognised tracker cookies (``_ga``, ``_fbp``, …) the site
    stores first-party via ``document.cookie``, restricted to vendors
    whose request module actually fired in this capture (so the
    attribution is certain, not name-only). These persist a per-visitor
    identifier and are lawful only behind consent, but they are
    first-party and no data has necessarily left — hence LOW, informative
    rather than alarmist. The forwarding/cloaking case is escalated to a
    HIGH finding (it explains the privacy cap); the rest stay LOW. Lazy
    import of the score helper avoids the builder ↔ score cycle.
    """
    from .score_v2 import forwarded_tracking_cookies

    findings: list[Finding] = []

    # HIGH: first-party cookies of a vendor forwarding/cloaking in this
    # capture — a disguised third party; this is what caps privacy.
    forwarded = forwarded_tracking_cookies(analysis)
    forwarded_names = {(c.name, c.host) for c in forwarded}
    if forwarded:
        fwd_by_vendor: dict[str, list[str]] = {}
        for cookie in forwarded:
            names = fwd_by_vendor.setdefault(cookie.vendor, [])
            if cookie.name not in names:
                names.append(cookie.name)
        fwd_vendors = sorted(fwd_by_vendor)
        fwd_bits = ", ".join(
            f"{v} ({', '.join(sorted(fwd_by_vendor[v]))})" for v in fwd_vendors
        )
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                "First-party tracking cookie behind a forwarding/cloaking "
                f"setup ({', '.join(fwd_vendors)})"
            ),
            detail=(
                "Set first-party but the vendor proxies / CNAME-cloaks, so the "
                f"identifier still reaches the third-party controller: {fwd_bits}. "
                "These count as cross-site tracking despite the first-party "
                "domain."
            ),
            action=(
                "Remove the forwarding/cloaking setup, or gate these cookies "
                "behind consent and drop them on reject."
            ),
            kind="forwarded_tracking_cookies",
        ))

    # LOW: the remaining first-party tracker cookies, restricted to
    # vendors whose request module actually fired (certain attribution).
    by_module = analysis.hits_by_module()
    by_vendor: dict[str, list[str]] = {}
    for cookie in analysis.cookies or []:
        if (cookie.name, cookie.host) in forwarded_names:
            continue
        module_id = getattr(cookie, "tracker_module_id", "")
        if not module_id or module_id not in by_module:
            continue
        if not getattr(cookie, "is_first_party", False):
            continue
        names = by_vendor.setdefault(cookie.vendor, [])
        if cookie.name not in names:
            names.append(cookie.name)

    if by_vendor:
        vendors = sorted(by_vendor)
        total = sum(len(v) for v in by_vendor.values())
        detail_bits = ", ".join(
            f"{vendor} ({', '.join(sorted(by_vendor[vendor]))})"
            for vendor in vendors
        )
        findings.append(Finding(
            severity=IMPACT_LOW,
            badge=SEVERITY_BADGES[IMPACT_LOW],
            headline=(
                f"{total} first-party tracking cookie{'s' if total != 1 else ''} "
                f"from {len(vendors)} vendor{'s' if len(vendors) != 1 else ''}"
            ),
            detail=(
                f"Set client-side via document.cookie: {detail_bits}. These "
                "persist a per-visitor identifier first-party, so they are "
                "invisible to Set-Cookie-only audits but are lawful only behind "
                "consent."
            ),
            action=(
                "Confirm these analytics/marketing cookies are gated behind "
                "consent and dropped on reject."
            ),
            kind="first_party_tracking_cookies",
        ))

    return findings


def _build_findings(
    analysis: Analysis, meta_by_id: dict[str, TrackerModule]
) -> list[Finding]:
    """Heuristic-driven board-level findings, severity-prioritized."""
    by_module = analysis.hits_by_module()
    findings: list[Finding] = []

    # 1. Session replay
    replay_present = sorted(SESSION_REPLAY_MODULES & by_module.keys())
    yandex_hits = by_module.get("yandex_metrica", [])
    if any(
        any(p.key == "(path) webvisor_counter_id" for p in h.params)
        for h in yandex_hits
    ) and "yandex_metrica" not in replay_present:
        replay_present.append("yandex_metrica")
    if replay_present:
        names = [
            by_module[m][0].module_name if m in by_module else m
            for m in replay_present
        ]
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline="Session replay active — every visitor interaction recorded",
            detail=(
                f"Vendor(s): {', '.join(names)}. Mouse moves, clicks, scroll, "
                "DOM mutations, form interactions are reconstructed server-side."
            ),
            action=(
                "Confirm a DPIA (GDPR Art. 35) covers the recording, and verify "
                "consent gating blocks the SDK until the visitor opts in."
            ),
        ))

    # 2. CNAME-cloaked trackers
    cloaks = _build_cname_cloaks(analysis)
    if cloaks:
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                f"{len(cloaks)} CNAME-cloaked tracker"
                f"{'s' if len(cloaks) != 1 else ''} — first-party-looking host"
                f"{'s' if len(cloaks) != 1 else ''} route to third-party vendors"
            ),
            detail=", ".join(
                f"{c.alias} → {c.canonical} [{c.vendor_module_name}]"
                for c in cloaks[:3]
            ) + ("…" if len(cloaks) > 3 else ""),
            action=(
                "Verify these aliased subdomains are disclosed in the privacy "
                "policy and CMP vendor list — they bypass tracker-protection "
                "blocklists by appearing first-party."
            ),
        ))

    # 3. Form-data egress
    form_post = sorted({
        mid for mid in (FORM_DATA_MODULES & by_module.keys())
        if any(h.method == "POST" for h in by_module[mid])
    })
    if form_post:
        names = [by_module[m][0].module_name for m in form_post]
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline="Form-data egress — submitted field values shipped to vendor",
            detail=f"Vendor(s): {', '.join(names)}.",
            action=(
                "Verify lawful basis (GDPR Art. 6) for sharing submitted form "
                "fields with these vendors; review what fields are forwarded."
            ),
        ))

    # 4. Persistent third-party tracking cookies
    set_cookie_high = 0
    cookie_vendors: set[str] = set()
    for hit in analysis.hits:
        for p in hit.params:
            if p.key.startswith("(set-cookie) ") and p.privacy_impact == IMPACT_HIGH:
                set_cookie_high += 1
                cookie_vendors.add(hit.module_name)
    if set_cookie_high:
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                f"{set_cookie_high} persistent cross-site tracking cookie"
                f"{'s' if set_cookie_high != 1 else ''} set"
            ),
            detail=(
                f"By vendor: {', '.join(sorted(cookie_vendors))}. "
                "These cookies carry ``SameSite=None`` and >30-day lifetimes — "
                "the modern cross-site-tracking signature."
            ),
            action=(
                "Audit the cookie banner — confirm tracking cookies are not set "
                "before the visitor consents (ePrivacy Directive)."
            ),
        ))

    # 4.25 YouTube embed cookies — a one-step fix worth calling out.
    # Lazy import: avoids the builder ↔ score import cycle.
    from .score_v2 import youtube_embed_cookie_count

    yt_cookies = youtube_embed_cookie_count(analysis)
    if yt_cookies:
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                f"YouTube embed sets {yt_cookies} persistent tracking "
                f"cookie{'s' if yt_cookies != 1 else ''} on page load"
            ),
            detail=(
                "The embedded YouTube player drops cross-site tracking "
                "cookies (SameSite=None, >30-day lifetime) the moment the "
                "page loads — before the visitor watches anything. This "
                "alone caps the privacy score."
            ),
            action=(
                "Switch the embed to youtube-nocookie.com (YouTube's "
                "privacy-enhanced mode — no cookies until the visitor "
                "clicks play). Better still, host the video on a European "
                "/ decentralised platform such as a PeerTube instance to "
                "avoid Google entirely."
            ),
            kind="youtube_embed_cookies",
        ))

    # 4.5 Consent-flow violations (pre-consent / post-reject tracking)
    findings.extend(_build_consent_findings(analysis))

    # 4.6 Supply-chain: third-party scripts without Subresource Integrity
    findings.extend(_build_sri_findings(analysis))
    findings.extend(_build_sri_protected_findings(analysis))

    # 4.7 First-party JS-set tracking cookies (informational)
    findings.extend(_build_first_party_tracking_cookie_findings(analysis))

    # 5. Extra-territorial vendor exposure
    high_risk: dict[str, list[str]] = {}
    for mid in by_module:
        meta = meta_by_id.get(mid)
        if meta is None or meta.legal_jurisdiction not in HIGH_RISK_JURISDICTIONS:
            continue
        short = _vendor_label(meta, by_module[mid][0].module_name)
        bucket = high_risk.setdefault(meta.legal_jurisdiction, [])
        if short not in bucket:
            bucket.append(short)
    if high_risk:
        total = sum(len(v) for v in high_risk.values())
        jur_summaries = [
            f"{len(v)}× {jur} ({', '.join(v[:3])}"
            f"{', +' + str(len(v) - 3) if len(v) > 3 else ''})"
            for jur, v in sorted(high_risk.items())
        ]
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                f"{total} vendor{'s' if total != 1 else ''} under extra-territorial "
                "jurisdiction (Schrems II / CLOUD Act / FISA 702 exposure)"
            ),
            detail="; ".join(jur_summaries),
            action=(
                "Verify Standard Contractual Clauses (SCCs) + Transfer Impact "
                "Assessments (TIAs) on file for each affected vendor under GDPR "
                "Art. 44–49."
            ),
        ))

    # 6. PII channels active
    pii_by_vendor: dict[str, set[str]] = {}
    for hit in analysis.hits:
        for p in hit.params:
            if p.privacy_impact != IMPACT_HIGH or p.category != CAT_PII:
                continue
            if p.key.startswith("(http) "):
                continue
            meta = meta_by_id.get(hit.module_id)
            vendor = _vendor_label(meta, hit.module_name)
            pii_by_vendor.setdefault(vendor, set()).add(_canonical_key(p.key))
    if pii_by_vendor:
        bits = []
        for vendor, keys in sorted(pii_by_vendor.items()):
            sample = ", ".join(sorted(keys)[:3])
            if len(keys) > 3:
                sample += f", +{len(keys) - 3}"
            bits.append(f"{vendor} ({sample})")
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                "PII channels active — direct or hashed personal identifiers "
                "captured"
            ),
            detail="; ".join(bits),
            action=(
                "Review each PII field against data-minimization "
                "(GDPR Art. 5(1)(c)) — is the field required for the documented "
                "processing purpose?"
            ),
        ))

    # 7. Cross-domain redirect
    m = analysis.manifest
    if m.landing_url and m.landing_url != m.target_url:
        target_reg = _registrable(m.target_url)
        landing_reg = _registrable(m.landing_url)
        if target_reg and landing_reg and target_reg != landing_reg:
            findings.append(Finding(
                severity=IMPACT_MEDIUM,
                badge=SEVERITY_BADGES[IMPACT_MEDIUM],
                headline="Cross-domain redirect on entry",
                detail=(
                    f"{target_reg} → {landing_reg}. First-party context for the "
                    "rest of the report is derived from the landing host."
                ),
            ))

    # 8. Unclassified third-party hosts
    untracked_3p = {
        ev.host for ev in analysis.untracked_requests
        if ev.host and analysis.is_third_party_host(ev.host)
    }
    if untracked_3p:
        sample = ", ".join(sorted(untracked_3p)[:3])
        if len(untracked_3p) > 3:
            sample += f", +{len(untracked_3p) - 3}"
        findings.append(Finding(
            severity=IMPACT_MEDIUM,
            badge=SEVERITY_BADGES[IMPACT_MEDIUM],
            headline=(
                f"{len(untracked_3p)} unclassified third-party host"
                f"{'s' if len(untracked_3p) != 1 else ''}"
            ),
            detail=f"Hosts: {sample}.",
            action=(
                "Investigate each unclassified host to determine whether a "
                "tracker module is needed or whether it can be safely ignored "
                "(e.g. operator-controlled CDN)."
            ),
        ))

    # 9. Visited first-party domains (informational)
    #
    # The session may span more than the base domain: a redirect entry
    # (museumpas.be → museumpassmusees.be) or a top-level page the visitor
    # navigated into (a chat tool on awel.sittool.net, a linked content
    # site). These are pages the visitor was actually on, so requests to
    # them are first-party, not third-party trackers. Surface them so the
    # report explains why those domains aren't in the third-party tally.
    extra_first_party = sorted(
        d for d in analysis.first_party_domains() if d and d != m.base_domain
    )
    if extra_first_party:
        findings.append(Finding(
            severity=IMPACT_LOW,
            badge=SEVERITY_BADGES[IMPACT_LOW],
            headline=(
                f"{len(extra_first_party)} additional first-party domain"
                f"{'s' if len(extra_first_party) != 1 else ''} visited"
            ),
            detail=(
                "The session navigated across these domains beyond "
                f"{m.base_domain or 'the base domain'}: "
                f"{', '.join(extra_first_party)}. Requests to them are treated "
                "as first-party (pages the visitor was on), not third-party "
                "trackers."
            ),
        ))

    # 10. DNS-posture findings for the first-party domain
    findings.extend(_build_dns_findings(analysis.dns_posture))

    # 11. Transport-posture findings (HTTPS hygiene + apex/www canon)
    findings.extend(_build_transport_findings(
        getattr(analysis, "transport_posture", None),
    ))

    # 11b. TLS-quality findings (cert validity/expiry + deprecated protocols)
    findings.extend(_build_tls_findings(
        getattr(analysis, "tls_posture", None),
    ))

    # 11c. Security-response-header posture (consolidated, when observed)
    findings.extend(_build_security_header_findings(analysis))

    # 12. Hidden extraterritorial-infrastructure findings (first-party
    #     host CNAMEs into a US-jurisdiction provider)
    findings.extend(_build_hidden_extraterritorial_findings(analysis))

    return findings


def _build_hidden_extraterritorial_findings(analysis: Analysis) -> list[Finding]:
    """Detect first-party hosts whose CNAME tail terminates in the US.

    The visible URL is on the operator's own domain, but the traffic
    reaches US-controlled infrastructure (Cloudflare, Akamai, Azure,
    AWS, Fastly, etc.) — a Schrems II / CLOUD Act exposure the URL
    alone does not reveal.

    One finding per host. Vendor / third-party hosts are deliberately
    excluded because their offshore exposure already surfaces via the
    existing per-vendor Schrems II rollup; firing here too would
    double-flag the same risk.
    """
    from ..cname_provider import cname_provider_from_chain

    chains = getattr(analysis, "cname_chains", {}) or {}
    if not chains:
        return []

    # Collect distinct first-party hosts contacted during the capture
    # (hits + untracked requests both count as "the visitor's browser
    # asked for this host"). Dedupe by host string.
    contacted: set[str] = set()
    for hit in analysis.hits:
        if hit.host:
            contacted.add(hit.host.lower())
    for ev in analysis.untracked_requests:
        if ev.host:
            contacted.add(ev.host.lower())

    out: list[Finding] = []
    for host in sorted(contacted):
        if analysis.is_third_party_host(host):
            continue
        chain = chains.get(host)
        if not chain:
            continue
        provider = cname_provider_from_chain(chain)
        if provider is None or provider.jurisdiction != "US":
            continue
        out.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                f"{host} (first-party) is fronted by {provider.name} "
                "— hidden extraterritorial infrastructure"
            ),
            detail=(
                f"The host {host} appears first-party in the URL but its "
                f"CNAME chain terminates at {provider.name} "
                f"({provider.jurisdiction}). Visitor traffic to what looks "
                "like the operator's own domain actually terminates on "
                f"{provider.jurisdiction}-controlled infrastructure — a "
                "Schrems II / CLOUD Act / FISA 702 exposure the URL alone "
                "does not reveal."
            ),
            action=(
                "Confirm Standard Contractual Clauses (SCCs) + Transfer "
                f"Impact Assessment (TIA) on file with {provider.name} "
                "for the data this domain carries. Consider EU-sovereign "
                "alternatives for sensitive endpoints."
            ),
            kind="hidden_extraterritorial_infra",
            source="capture",
        ))
    return out


def _build_transport_findings(posture) -> list[Finding]:
    """Convert :class:`TransportFinding` objects to executive ``Finding``s.

    The transport module produces severity / headline / detail tuples
    that already match the report's finding shape — this wrapper just
    decorates each with the canonical severity badge and a remediation
    action sized for the executive summary.
    """
    if posture is None:
        return []
    from ..http_posture.findings import derive_findings

    actions = {
        "high": (
            "Restore TLS service on the captured host. Without HTTPS the "
            "site cannot meet baseline GDPR/eIDAS confidentiality."
        ),
        "medium": (
            "Configure a 301 redirect from HTTP to HTTPS (or apex ↔ www) "
            "so the canonical, encrypted host is the only landing point."
        ),
        "low": (
            "Worth noting in the audit summary; no immediate remediation."
        ),
    }
    findings: list[Finding] = []
    for tf in derive_findings(posture):
        findings.append(Finding(
            severity=tf.severity,
            badge=SEVERITY_BADGES.get(tf.severity, ""),
            headline=tf.headline,
            detail=tf.detail,
            action=actions.get(tf.severity, ""),
        ))
    return findings


def _build_tls_findings(tls) -> list[Finding]:
    """Convert TLS-quality findings to executive ``Finding``s.

    Reuses the shared :class:`TransportFinding` shape via
    :func:`~leak_inspector.http_posture.findings.derive_tls_findings`,
    decorating each with the canonical severity badge and a remediation
    action sized for the executive summary.
    """
    if tls is None:
        return []
    from ..http_posture.findings import derive_tls_findings

    actions = {
        "high": (
            "Install a valid, CA-issued certificate matching the hostname. "
            "An unauthenticated TLS connection cannot meet baseline "
            "GDPR/NIS2 confidentiality."
        ),
        "medium": (
            "Disable TLS 1.0/1.1 and serve only TLS 1.2+ — deprecated "
            "protocols are a NIS2/PCI failure."
        ),
        "low": (
            "Confirm automated certificate renewal so the certificate "
            "does not lapse."
        ),
    }
    findings: list[Finding] = []
    for tf in derive_tls_findings(tls):
        findings.append(Finding(
            severity=tf.severity,
            badge=SEVERITY_BADGES.get(tf.severity, ""),
            headline=tf.headline,
            detail=tf.detail,
            action=actions.get(tf.severity, ""),
        ))
    return findings


def _build_security_header_checks(analysis):
    """Evaluate the captured main-document security headers for the report.

    Thin adapter over
    :func:`~leak_inspector.report.score_v2.evaluate_security_headers`
    (the single source of truth shared with the score). Returns ``None``
    when no document response was observed — renderers then stay silent.
    """
    from .score_v2 import evaluate_security_headers

    return evaluate_security_headers(
        getattr(analysis, "security_headers", None)
    )


#: The one header whose absence is MEDIUM rather than LOW — CSP is the
#: primary in-page XSS / injection mitigation (matches its 1.0 score
#: weight against the others' 0.5).
_MEANINGFUL_HEADER_KEY = "content-security-policy"


def _build_security_header_findings(analysis) -> list[Finding]:
    """One consolidated finding when observed security headers are missing.

    The per-header detail already renders in the "Security headers"
    section; the executive summary gets a single rolled-up line rather
    than up to six. Silent when no document response was observed
    (posture unknown — the certainty rule) or when every header is
    present. Severity is MEDIUM when Content-Security-Policy is among
    the missing, otherwise LOW.
    """
    checks = _build_security_header_checks(analysis)
    if not checks:
        return []
    missing = [c for c in checks if not c.ok]
    if not missing:
        return []
    labels = [c.label for c in missing]
    csp_missing = any(c.key == _MEANINGFUL_HEADER_KEY for c in missing)
    severity = IMPACT_MEDIUM if csp_missing else IMPACT_LOW
    return [Finding(
        severity=severity,
        badge=SEVERITY_BADGES[severity],
        headline=(
            f"{len(missing)} security response "
            f"header{'s' if len(missing) != 1 else ''} missing on the "
            "main document"
        ),
        detail=(
            "The landing page response omits: " + ", ".join(labels) + ". "
            "These headers harden the page against XSS, clickjacking, "
            "MIME-sniffing and referrer leakage; see the Security headers "
            "section for the full per-header status."
        ),
        action=(
            "Set the missing headers at the server/edge. At minimum send a "
            "Content-Security-Policy, Strict-Transport-Security, "
            "X-Content-Type-Options: nosniff and X-Frame-Options."
        ),
        kind="security_headers_missing",
    )]


def _build_dns_findings(posture: DNSPosture | None) -> list[Finding]:
    """Translate the first-party DNS-posture snapshot into executive findings.

    Surfaces the four signals most worth a board-level mention:

    * Where the web origin, DNS, and mail provider are hosted — each is a
      separate Schrems II / CLOUD Act exposure.
    * Email authentication posture (SPF / DMARC) — both reflect whether
      attackers can spoof the brand and whether outbound mail is
      authenticated.
    * DNSSEC presence — an unsigned zone is more easily hijacked.
    * Self-disclosed SaaS verifications — third-party data flows
      published by the operator themselves.
    """
    if posture is None:
        return []
    findings: list[Finding] = []

    # --- hosting / DNS / mail provider jurisdictions ----------------------
    hosting_jurisdictions: dict[str, list[str]] = {}
    for ip in posture.a_records + posture.aaaa_records:
        if ip.country_code in HIGH_RISK_JURISDICTIONS:
            label = ip.as_org or ip.address
            hosting_jurisdictions.setdefault(ip.country_code, []).append(label)
    if hosting_jurisdictions:
        bits = []
        for jur, providers in sorted(hosting_jurisdictions.items()):
            unique = sorted(set(providers))[:3]
            bits.append(f"{jur} ({', '.join(unique)})")
        findings.append(Finding(
            severity=IMPACT_HIGH,
            badge=SEVERITY_BADGES[IMPACT_HIGH],
            headline=(
                "First-party web infrastructure hosted under extra-territorial "
                "jurisdiction"
            ),
            detail="; ".join(bits) + ".",
            action=(
                "Verify whether SCCs + a Transfer Impact Assessment cover the "
                "first-party hosting arrangement (GDPR Art. 44–49)."
            ),
        ))

    dns_provider_jurisdictions: dict[str, list[str]] = {}
    for ns in posture.nameservers:
        for ip in ns.ips:
            if ip.country_code in HIGH_RISK_JURISDICTIONS:
                label = ns.provider or ip.as_org or ns.name
                dns_provider_jurisdictions.setdefault(ip.country_code, []).append(label)
                break
    if dns_provider_jurisdictions:
        bits = []
        for jur, providers in sorted(dns_provider_jurisdictions.items()):
            unique = sorted(set(providers))[:3]
            bits.append(f"{jur} ({', '.join(unique)})")
        findings.append(Finding(
            severity=IMPACT_MEDIUM,
            badge=SEVERITY_BADGES[IMPACT_MEDIUM],
            headline="Authoritative DNS hosted under extra-territorial jurisdiction",
            detail="; ".join(bits) + ".",
            action=(
                "DNS-provider sovereignty is often overlooked — confirm the "
                "authoritative-DNS provider is acceptable under the same "
                "transfer-risk policy that governs hosting and analytics."
            ),
        ))

    mail_jurisdictions: dict[str, list[str]] = {}
    for mx in posture.mx:
        for ip in mx.ips:
            if ip.country_code in HIGH_RISK_JURISDICTIONS:
                provider = _provider_label_from_org(ip.as_org) or mx.name
                mail_jurisdictions.setdefault(ip.country_code, []).append(provider)
                break
    if mail_jurisdictions:
        bits = []
        for jur, providers in sorted(mail_jurisdictions.items()):
            unique = sorted(set(providers))[:3]
            bits.append(f"{jur} ({', '.join(unique)})")
        findings.append(Finding(
            severity=IMPACT_MEDIUM,
            badge=SEVERITY_BADGES[IMPACT_MEDIUM],
            headline="Inbound mail handled by an extra-territorial provider",
            detail="; ".join(bits) + ".",
            action=(
                "Inbound email contains personal data of every correspondent — "
                "verify the SCC / TIA covers the MX provider, not just the "
                "operator's own mailboxes."
            ),
        ))

    # --- email authentication posture -------------------------------------
    if posture.spf is None:
        findings.append(Finding(
            severity=IMPACT_MEDIUM,
            badge=SEVERITY_BADGES[IMPACT_MEDIUM],
            headline="No SPF record published",
            detail=(
                "Outbound mail from this domain cannot be authenticated against "
                "an allowlist; recipient servers cannot tell spoofed mail from "
                "the genuine article."
            ),
            action=(
                "Publish an SPF record (TXT v=spf1) that enumerates the "
                "operator's mail vendors and terminates with ``-all``."
            ),
        ))
    elif posture.spf.final_qualifier in ("+all", "?all"):
        sev = IMPACT_HIGH if posture.spf.final_qualifier == "+all" else IMPACT_MEDIUM
        findings.append(Finding(
            severity=sev,
            badge=SEVERITY_BADGES[sev],
            headline=(
                f"SPF ends with ``{posture.spf.final_qualifier}`` — "
                "permits unauthenticated senders"
            ),
            detail=(
                "Anyone (``+all``) or any sender not explicitly denied (``?all``) "
                "can claim to send from this domain. Spoofing succeeds against "
                "any recipient that honours SPF."
            ),
            action="Tighten the SPF policy to ``-all`` (or at minimum ``~all``).",
        ))

    if posture.dmarc is None:
        findings.append(Finding(
            severity=IMPACT_MEDIUM,
            badge=SEVERITY_BADGES[IMPACT_MEDIUM],
            headline="No DMARC record published",
            detail=(
                "Recipient servers have no policy to act on SPF/DKIM failures — "
                "spoofed mail is not rejected and no aggregate reports flow back."
            ),
            action=(
                "Publish a DMARC record at ``_dmarc.<domain>`` starting at "
                "``p=none`` with ``rua`` reporting; ramp to ``p=quarantine`` "
                "then ``p=reject`` once SPF/DKIM coverage is verified."
            ),
        ))
    elif posture.dmarc.policy in ("", "none"):
        findings.append(Finding(
            severity=IMPACT_MEDIUM,
            badge=SEVERITY_BADGES[IMPACT_MEDIUM],
            headline="DMARC in monitor-only mode (``p=none``)",
            detail=(
                "Policy is published but spoofed mail is delivered to recipients "
                "unchanged — only aggregate reports flow back to the operator."
            ),
            action=(
                "Once aggregate reports show legitimate senders aligned, ramp "
                "DMARC policy from ``p=none`` to ``p=quarantine`` and then "
                "``p=reject``."
            ),
            kind="dmarc_p_none",
        ))

    # --- DNSSEC -----------------------------------------------------------
    # Signed zones get a positive 🟢 finding so a manager scanning the
    # executive summary sees "this is done right" alongside the actionable
    # items. Unsigned (or broken-chain) zones get the actionable MEDIUM
    # finding asking for DS+DNSKEY deployment.
    if posture.dnssec is not None:
        if posture.dnssec.parent_has_ds and posture.dnssec.zone_has_dnskey:
            findings.append(Finding(
                severity=IMPACT_LOW,
                badge=SEVERITY_BADGES[IMPACT_LOW],
                headline="Zone is DNSSEC-signed",
                detail=posture.dnssec.summary,
                source="dns",
                kind="dnssec_signed",
            ))
        else:
            findings.append(Finding(
                severity=IMPACT_MEDIUM,
                badge=SEVERITY_BADGES[IMPACT_MEDIUM],
                headline="Zone is not DNSSEC-signed",
                detail=posture.dnssec.summary,
                action=(
                    "Enable DNSSEC at the DNS provider and publish DS records at "
                    "the registrar so cache-poisoning attacks against this zone fail."
                ),
                source="dns",
            ))

    # --- IPv6 reachability ------------------------------------------------
    # A small infrastructure-modernity signal: a primary host with AAAA
    # records is reachable over IPv6 (a green positive); one without is
    # IPv4-only (a minor LOW gap with an action). Mirrors the DNSSEC split.
    if posture.aaaa_records:
        findings.append(Finding(
            severity=IMPACT_LOW,
            badge=SEVERITY_BADGES[IMPACT_LOW],
            headline="Reachable over IPv6",
            detail=(
                "The primary host publishes AAAA records — visitors on "
                "IPv6-only networks reach it directly, without a "
                "carrier-grade-NAT or translation hop."
            ),
            source="dns",
            kind="ipv6_supported",
        ))
    else:
        findings.append(Finding(
            severity=IMPACT_LOW,
            badge=SEVERITY_BADGES[IMPACT_LOW],
            headline="Not reachable over IPv6",
            detail=(
                "The primary host publishes no AAAA record — it is reachable "
                "over legacy IPv4 only. Visitors on IPv6-only networks depend "
                "on a translation hop outside the operator's control."
            ),
            action=(
                "Publish AAAA records and enable IPv6 at the host / CDN so the "
                "site is reachable natively over IPv6."
            ),
            source="dns",
            kind="ipv6_absent",
        ))

    # --- self-disclosed SaaS verifications --------------------------------
    if posture.txt_verifications:
        vendor_jurisdictions: dict[str, list[str]] = {}
        for txt in posture.txt_verifications:
            jur = txt.jurisdiction or "??"
            vendor_jurisdictions.setdefault(jur, []).append(txt.vendor)
        total = sum(len(v) for v in vendor_jurisdictions.values())
        bits = []
        for jur, vendors in sorted(vendor_jurisdictions.items()):
            unique = sorted(set(vendors))
            sample = ", ".join(unique[:3])
            if len(unique) > 3:
                sample += f", +{len(unique) - 3}"
            bits.append(f"{jur}: {sample}")
        # Severity: HIGH if any high-risk jurisdiction is present, else MEDIUM.
        sev = (
            IMPACT_HIGH
            if any(j in HIGH_RISK_JURISDICTIONS for j in vendor_jurisdictions)
            else IMPACT_MEDIUM
        )
        findings.append(Finding(
            severity=sev,
            badge=SEVERITY_BADGES[sev],
            headline=(
                f"{total} third-party SaaS relationship"
                f"{'s' if total != 1 else ''} self-disclosed via DNS"
            ),
            detail="; ".join(bits) + ".",
            action=(
                "Each TXT verification token is a published admission of using "
                "that vendor — cross-check the list against the vendor register "
                "and the privacy policy."
            ),
        ))

    # Stamp every DNS-derived finding with source="dns" in one place,
    # rather than threading the kwarg through every Finding(...) call
    # above. The split lets renderers group findings under a labelled
    # "Back-office" heading distinct from website/capture findings.
    from dataclasses import replace
    return [replace(f, source="dns") for f in findings]


def _provider_label_from_org(as_org: str) -> str:
    """Friendly provider label for an AS-org string used in finding details.

    Mirrors :func:`leak_inspector.dns_posture.sovereignty.asn_to_provider`
    but kept here to avoid a builder→sovereignty import cycle for what is
    a one-line lookup.
    """
    if not as_org:
        return ""
    upper = as_org.upper()
    for needle, label in (
        ("CLOUDFLARE", "Cloudflare"),
        ("AMAZON",     "Amazon"),
        ("GOOGLE",     "Google"),
        ("MICROSOFT",  "Microsoft"),
        ("AKAMAI",     "Akamai"),
    ):
        if needle in upper:
            return label
    return as_org


def _build_actions(findings: list[Finding]) -> list[str]:
    """Deduplicate action strings from findings, preserving order."""
    seen: set[str] = set()
    out: list[str] = []
    for finding in findings:
        if not finding.action or finding.action in seen:
            continue
        seen.add(finding.action)
        out.append(finding.action)
    return out


def _build_stats(
    analysis: Analysis, meta_by_id: dict[str, TrackerModule]
) -> SummaryStats:
    """Aggregate volume statistics + top-by-impact ranking."""
    by_module = analysis.hits_by_module()
    tracked_hosts = {h.host for h in analysis.hits}
    untracked_3p = {
        ev.host for ev in analysis.untracked_requests
        if ev.host and analysis.is_third_party_host(ev.host)
    }
    return SummaryStats(
        trackers_fired=len(by_module),
        total_requests=len(analysis.hits),
        unique_requests=len(analysis.representative_hits()),
        third_party_hosts_touched=len(tracked_hosts) + len(untracked_3p),
        third_party_hosts_claimed=len(tracked_hosts),
        third_party_hosts_unclassified=len(untracked_3p),
        top_by_impact=_build_top_by_impact(analysis, meta_by_id),
    )


# ---------------------------------------------------------------------------
# Per-tracker drill-down
# ---------------------------------------------------------------------------


def _build_vendor_meta(meta: TrackerModule | None) -> VendorMeta:
    if meta is None:
        return VendorMeta()
    flag, is_eu = _country_flag(meta.legal_jurisdiction)
    return VendorMeta(
        vendor=meta.vendor or "",
        legal_jurisdiction=meta.legal_jurisdiction or "",
        flag=flag,
        is_eu=is_eu,
        data_residency=meta.data_residency or "",
        sovereignty_notes=meta.sovereignty_notes or "",
        tooltip=_build_vendor_tooltip(meta),
    )


def _build_param_rows(params: Iterable[ParamInfo]) -> list[ParamRow]:
    return [
        ParamRow(
            key=p.key,
            value=str(p.value),
            category=p.category,
            privacy_impact=p.privacy_impact,
            meaning=p.meaning or "",
        )
        for p in params
    ]


def _build_module_sections(
    analysis: Analysis, meta_by_id: dict[str, TrackerModule]
) -> list[ModuleSection]:
    """One :class:`ModuleSection` per fired module, in registration order."""
    grouped: dict[str, list[Hit]] = {}
    # representative_hits is per-module dedup'd; group those by module.
    for rep in analysis.representative_hits():
        grouped.setdefault(rep.module_id, []).append(rep)

    raw_by_module = analysis.hits_by_module()
    sections: list[ModuleSection] = []
    for module_id, reps in grouped.items():
        raw_hits = raw_by_module.get(module_id, [])
        if not raw_hits:
            continue
        meta = meta_by_id.get(module_id)
        module_name = raw_hits[0].module_name

        # Category counts across raw hits.
        cat_counts: Counter[str] = Counter()
        for hit in raw_hits:
            for p in hit.params:
                cat_counts[p.category] += 1

        # Harvested-fields summary — top N keys across raw hits, most-
        # sensitive category retained for each key.
        key_counts: Counter[str] = Counter()
        key_category: dict[str, str] = {}
        for hit in raw_hits:
            for p in hit.params:
                canonical = _canonical_key(p.key)
                key_counts[canonical] += 1
                existing = key_category.get(canonical)
                if existing != CAT_PII and p.category == CAT_PII:
                    key_category[canonical] = CAT_PII
                elif existing not in (CAT_PII, CAT_IDENTIFIER) and \
                        p.category == CAT_IDENTIFIER:
                    key_category[canonical] = CAT_IDENTIFIER
                elif existing is None:
                    key_category[canonical] = p.category
        harvested = [
            HarvestedField(
                key=k,
                category=key_category.get(k, "other"),
                count=n,
            )
            for k, n in key_counts.most_common()
        ]

        unique_param_keys = len(key_counts)

        # Representative hits.
        reps_doc = [
            RepresentativeHit(
                method=rep.method,
                url=rep.url,
                host=rep.host,
                response_status=rep.response_status,
                collapsed_event_count=len(rep.events),
                event_ids=list(rep.events),
                request_body=rep.request_body,
                response_body=rep.response_body,
                params=_build_param_rows(rep.params),
            )
            for rep in reps
        ]

        sections.append(ModuleSection(
            module_id=module_id,
            module_name=module_name,
            vendor_meta=_build_vendor_meta(meta),
            total_hits=len(raw_hits),
            representative_count=len(reps),
            unique_param_keys=unique_param_keys,
            category_counts=dict(cat_counts),
            harvested_fields=harvested,
            representative_hits=reps_doc,
        ))
    return sections


# ---------------------------------------------------------------------------
# Unclassified hosts
# ---------------------------------------------------------------------------


def _build_unclassified_hosts(analysis: Analysis) -> list[UnclassifiedHost]:
    """Convert :func:`collect_unknown_hosts` output into document dataclasses.

    Stamps each host's ``cdn_provider`` from its CNAME chain when one
    is available — explains "why is this host unclassified?" as
    "first-party hosting fronted by <CDN>" rather than leaving the
    auditor guessing.
    """
    from ..cname_provider import cname_provider_from_chain

    chains = getattr(analysis, "cname_chains", {}) or {}
    out: list[UnclassifiedHost] = []
    for host in collect_unknown_hosts(analysis):
        provider = cname_provider_from_chain(chains.get(host.host.lower()))
        out.append(UnclassifiedHost(
            host=host.host,
            count=host.count,
            methods=dict(host.methods),
            statuses={str(k): v for k, v in host.statuses.items()},
            sample_urls=[SampleUrl(method=m, url=u) for m, u in host.sample_urls],
            param_samples=dict(host.param_samples),
            first_initiator=host.first_initiator,
            first_event_id=host.first_event_id,
            first_timestamp=host.first_timestamp,
            cdn_provider=provider,
        ))
    return out


# ---------------------------------------------------------------------------
# Manifest view
# ---------------------------------------------------------------------------


def _build_manifest_view(
    analysis: Analysis, display_name: str | None = None
) -> ManifestView:
    m = analysis.manifest
    browser = m.browser if isinstance(m.browser, dict) else {}
    return ManifestView(
        target_url=m.target_url,
        landing_url=m.landing_url or "",
        base_domain=m.base_domain,
        session_id=m.session_id,
        started_at=m.started_at,
        ended_at=m.ended_at,
        profile=m.profile,
        browser_name=str(browser.get("name", "")),
        browser_version=str(browser.get("version", "")),
        raw=m.to_dict(),
        display_name=display_name,
    )


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def build_report_document(
    analysis: Analysis,
    *,
    module_meta_by_id: dict[str, TrackerModule] | None = None,
    display_name: str | None = None,
) -> ReportDocument:
    """Build a :class:`ReportDocument` from an :class:`Analysis`.

    ``display_name`` (optional) overrides the report's title label — the
    host is used when it is None. The bulk runner passes a site's name
    from its ``domains.csv`` ``name`` column.

    ``module_meta_by_id`` is a registry of TrackerModule instances keyed
    by ``module_id`` — typically built once from
    :func:`leak_inspector.modules.all_modules`. When omitted, vendor
    metadata is sourced from the modules currently in the registry.
    """
    if module_meta_by_id is None:
        # Lazy import — modules import some of this report layer too
        # (debug.py), so deferring keeps the cycle clean.
        from ..modules import all_modules
        module_meta_by_id = {m.module_id: m for m in all_modules()}

    # Apply the date-dependent EOL judgment up front and stamp it back
    # onto the analysis: the security score's eol_platform signal reads
    # is_eol off analysis.cms_fingerprint (via build_deductions). The
    # passive detector leaves is_eol at its safe default, so without this
    # write-back the signal would never fire.
    analysis.cms_fingerprint = _judge_cms_eol(
        getattr(analysis, "cms_fingerprint", None)
    )

    findings = _build_findings(analysis, module_meta_by_id)
    exec_summary = ExecutiveSummary(
        findings=findings,
        actions=_build_actions(findings),
        cname_cloak_tooltip=CNAME_CLOAK_TOOLTIP,
        cname_cloaks=_build_cname_cloaks(analysis),
        high_impact_by_vendor=_build_high_impact_by_vendor(analysis, module_meta_by_id),
        jurisdictions=_build_jurisdictions(analysis, module_meta_by_id),
        stats=_build_stats(analysis, module_meta_by_id),
    )

    return ReportDocument(
        schema_version=SCHEMA_VERSION,
        manifest=_build_manifest_view(analysis, display_name),
        executive_summary=exec_summary,
        trackers=_build_module_sections(analysis, module_meta_by_id),
        unclassified_hosts=_build_unclassified_hosts(analysis),
        dns_posture=analysis.dns_posture,
        enriched_at=getattr(analysis, "enriched_at", None),
        section_timestamps=dict(getattr(analysis, "section_timestamps", {}) or {}),
        capture_status=determine_capture_status(analysis),
        cookies=list(getattr(analysis, "cookies", []) or []),
        forwarded_cookie_keys=_build_forwarded_cookie_keys(analysis),
        storage=list(getattr(analysis, "storage", []) or []),
        cms_fingerprint=analysis.cms_fingerprint,
        transport_posture=getattr(analysis, "transport_posture", None),
        tls_posture=getattr(analysis, "tls_posture", None),
        security_txt=getattr(analysis, "security_txt", None),
        security_headers=_build_security_header_checks(analysis),
        verdict=_build_verdict(analysis),
        score=_build_score(analysis, module_meta_by_id),
        consent=getattr(analysis, "consent", None),
        cyberfundamentals=_build_cyberfundamentals(analysis),
    )


def _build_cyberfundamentals(analysis: Analysis):
    """Build the NIS2 / CyberFundamentals baseline view.

    Lazy-imported to avoid a builder ↔ nis2 cycle. Reuses the judged CMS
    fingerprint already stamped onto ``analysis`` (so the end-of-life
    control sees it).
    """
    from .nis2 import build_cyberfundamentals_view
    return build_cyberfundamentals_view(analysis)


def _build_score(analysis: Analysis, module_meta_by_id):
    """Build the Scoring-v2 score view (cumulative impact → logistic).

    Lazy-imported to avoid a builder ↔ score_v2 cycle. The judged CMS
    fingerprint has already been stamped onto ``analysis`` above, so the
    ``eol_platform`` signal sees it.
    """
    from .score_v2 import build_score_view
    return build_score_view(analysis, module_meta_by_id)


def _build_forwarded_cookie_keys(analysis: Analysis) -> list[tuple[str, str]]:
    """``(name, host)`` keys of forwarded first-party tracker cookies.

    Delegates to the scoring helper (the single definition of
    "forwarded": vendor cloak/proxy-marked in this capture + persistent
    cookie), deduped and sorted so the document is deterministic. Lazy
    import avoids the builder ↔ score cycle.
    """
    from .score_v2 import forwarded_tracking_cookies
    return sorted({
        (c.name, c.host) for c in forwarded_tracking_cookies(analysis)
    })


def _build_verdict(analysis: Analysis):
    """Construct the manager-facing verdict for the report.

    Lazy-imported so the (minimal) verdict module doesn't pull on the
    rest of the report layer during low-level Analysis construction.
    """
    from .verdict import build_verdict
    return build_verdict(analysis)


def _judge_cms_eol(fp):
    """Apply hard-EOL judgment at document-build time.

    Kept separate from passive detection / probing because EOL status
    depends on today's date: a version that's supported when captured
    may be EOL by the time the report is rendered.
    """
    if fp is None:
        return None
    from datetime import date

    from ..cms.eol import apply_eol_judgment

    return apply_eol_judgment(fp, today=date.today())


def determine_capture_status(analysis: Analysis) -> "CaptureStatus":
    """Classify whether the landing-page load actually succeeded.

    Walks the captured events for the request whose URL matches
    ``manifest.landing_url`` (or, failing that, ``manifest.target_url``)
    and inspects its ``response_status``:

    * 2xx / 3xx → healthy (the redirect chain typically lands at 2xx).
    * 4xx / 5xx → HTTP error; ``reason`` is the standard reason phrase.
    * ``None`` (request fired but never got a response — DNS / TCP /
      TLS failure) or no matching request at all → "Unreachable".
    """
    from http import HTTPStatus
    from .document import CaptureStatus

    landing = analysis.manifest.landing_url or analysis.manifest.target_url
    target = analysis.manifest.target_url

    matching_status: int | None = None
    found_matching = False
    # Prefer the LAST request whose URL matches landing_url (final
    # link in the redirect chain). Fall back to target_url if no
    # landing match exists. URLs are compared trailing-slash-normalized
    # so a bare-domain target (``https://host``) matches the document the
    # browser fetched as ``https://host/``. ``analysis.hits`` covers
    # tracker-claimed requests; ``untracked_requests`` covers everything else.
    for url in (landing, target):
        if not url:
            continue
        norm = _normalize_url(url)
        for ev in _all_request_events(analysis):
            if _normalize_url(ev.url) == norm:
                matching_status = ev.response_status
                found_matching = True
        if found_matching:
            break

    if not found_matching:
        # SPA / host-changing-redirect gap: the landing/target URL never
        # appeared as a network request (e.g. an Angular app that
        # client-side-routes to ``/home``). Fall back to the document the
        # browser actually landed on.
        document = _landing_document_event(analysis)
        if document is not None:
            matching_status = document.response_status
            found_matching = True

    if not found_matching or matching_status is None:
        return CaptureStatus(
            http_status=None, reason="Unreachable", is_failure=True,
        )
    if matching_status >= 400:
        try:
            phrase = HTTPStatus(matching_status).phrase
        except ValueError:
            phrase = "Unknown error"
        return CaptureStatus(
            http_status=matching_status, reason=phrase, is_failure=True,
        )
    try:
        phrase = HTTPStatus(matching_status).phrase or "OK"
    except ValueError:
        phrase = "OK"
    return CaptureStatus(
        http_status=matching_status, reason=phrase, is_failure=False,
    )


def _all_request_events(analysis: Analysis):
    """Iterator over every RequestEvent the analysis saw — both tracker
    hits and unclassified requests. Used by :func:`determine_capture_status`
    to find the landing-page document request without having to re-open
    the bundle."""
    for hit in analysis.hits:
        # Hits carry the same url / response_status fields we need.
        yield hit
    for ev in analysis.untracked_requests:
        yield ev


def _normalize_url(url: str | None) -> str:
    """Strip trailing slashes so ``https://host`` and ``https://host/`` compare
    equal — browsers append ``/`` to a bare-origin navigation's path."""
    return url.rstrip("/") if url else ""


def _landing_document_event(analysis: Analysis):
    """Return the last top-level document request, or ``None``.

    A request is a top-level document load when its ``Sec-Fetch-Dest``
    header is ``document``. The final such request is the page the browser
    landed on — the fallback used when neither landing nor target URL can
    be matched directly (single-page apps, host-changing redirects)."""
    last = None
    for ev in _all_request_events(analysis):
        # ``analysis.hits`` yields Hit objects that lack request headers;
        # only RequestEvents carry the Sec-Fetch-Dest we need.
        if _header_value(getattr(ev, "headers", None), "sec-fetch-dest") == "document":
            last = ev
    return last


def _header_value(headers: dict | None, name: str) -> str | None:
    """Case-insensitive lookup of a request header value."""
    if not headers:
        return None
    lname = name.lower()
    for key, value in headers.items():
        if key.lower() == lname:
            return value
    return None


__all__ = [
    "CATEGORY_DESCRIPTIONS",
    "CNAME_CLOAK_TOOLTIP",
    "EU_MEMBERS",
    "FORM_DATA_MODULES",
    "HIGH_RISK_JURISDICTIONS",
    "SESSION_REPLAY_MODULES",
    "SEVERITY_BADGES",
    "build_report_document",
    "determine_capture_status",
]
