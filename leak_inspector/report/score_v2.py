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

"""The scoring engine: cumulative impact deduction → logistic dimensions.

This is the project's scoring module (it replaced the v1 checklist
model; see ``docs/SCORING.md`` for the operational write-up and
``docs/SCORING.md`` for the 33-criteria rubric). Every fired
tracker module and every fired non-module signal carries a curated
:class:`~leak_inspector.impact.ImpactRating`; per domain the impacts
**cumulate** into a penalty, which a **logistic curve** maps to a 0–100
dimension score; the three dimensions combine by **cube root** into the
total. Both ends are asymptotes (perfection and rock-bottom are never
quite reached); displayed scores ceil-round so 1 and 99 are the printed
bounds.

The pipeline, top to bottom:

* :func:`build_score_view` — the report entry point. Assembles the
  deductions, scores them, and adapts the result to the renderer/bulk
  interface (:class:`ScoreView` / :class:`DimensionView`). Returns
  ``None`` for an un-enriched bundle (no posture to score honestly).
* :func:`build_deductions` — one Analysis → the full deduction list:
  module rows (each module's :meth:`effective_rating` over its own
  hits, so per-capture variants apply) + non-module signal rows mapped
  from real facts (:func:`_signal_deductions`).
* :func:`module_deductions` — module rows, **once per distinct module**
  regardless of hit count and per *product* (three Google products are
  three deductions); unrated modules deduct nothing but are named.
* :func:`compute_score_logistic` / :func:`logistic_score` — the curve.
* the posture predicates below — pure ``Analysis`` checks the signal
  assembler keys on (moved here from the retired v1 ``score`` module).

:func:`compute_score_v2` is a retained linear-floor variant
(``max(0, 10 − Σ impacts)``) used only by its own tests; the report
path is the logistic one.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from ..http_posture.findings import CERT_EXPIRY_WARN_DAYS
from ..impact import ImpactRating

#: The three rating domains, in scorecard order.
DOMAINS: tuple[str, ...] = ("privacy", "security", "resilience")

#: A per-dimension ceiling: ``(max_stars, reason)``.
Cap = tuple[float, str]


# ---------------------------------------------------------------------------
# Posture predicates (moved here from the retired v1 score module)
# ---------------------------------------------------------------------------
# Pure functions over an Analysis used by the signal assembler to decide
# which non-module signals fired. Each returns the *adverse fact* or the
# data behind it; the certainty rule (only fire when data is present and
# adverse) is applied by the caller.

#: DMARC policies that count as "strict" (reject / quarantine); ``p=none``
#: is monitor-only and does not count.
_DMARC_STRICT_POLICIES: frozenset[str] = frozenset({"quarantine", "reject"})

#: SPF ``all``-qualifiers that adequately restrict the sender set: hard
#: fail (``-all``) and soft fail (``~all``). Anything else (``+all``
#: pass-all, ``?all`` neutral, or no record) leaves the domain spoofable.
_SPF_ACCEPTABLE_QUALIFIERS: frozenset[str] = frozenset({"-all", "~all"})

#: A persistent cross-site cookie has a lifetime above this many days.
_PERSISTENT_COOKIE_DAYS_THRESHOLD = 30.0

#: ParamInfo key prefixes proving a hit lands at a third party despite a
#: first-party-looking host (CNAME cloak / reverse proxy).
_FIRST_PARTY_OVERRIDE_PREFIXES: tuple[str, ...] = ("(cname-cloak)", "(fp-proxy)")

#: A forwarding/cloaking marker attributes the technique to the proxy
#: module; this maps it back to the vendor whose data it forwards.
_FORWARDING_BRIDGE: dict[str, str] = {"google_first_party_mode": "ga4"}

#: Vendor label of the YouTube embed (the one-step youtube-nocookie fix).
_YOUTUBE_EMBED_VENDOR = "YouTube (embedded player)"


def format_stars(value: int | float) -> str:
    """Render a dimension score, dropping a trailing ``.0`` (``8.0``/``8``
    → ``"8"``; ``7.5`` → ``"7.5"``)."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _cloak_or_proxy_marked(hit) -> bool:
    """True when a hit carries a CNAME-cloak or reverse-proxy marker."""
    return any(
        p.key.startswith(_FIRST_PARTY_OVERRIDE_PREFIXES) for p in hit.params
    )


def _outside_eu(code: str) -> bool:
    """``True`` when ``code`` is a known country code outside the EU.

    Empty codes (no data) return ``False`` — we never penalise a
    jurisdiction we could not determine. ``"EU"`` is treated as inside.
    """
    from .builder import EU_MEMBERS  # lazy: avoid the builder↔score_v2 cycle

    c = (code or "").strip().upper()
    return bool(c) and c != "EU" and c not in EU_MEMBERS


#: Team Cymru appends the ASN's registration country as a trailing
#: ``", CC"`` to the AS-org string — the fallback jurisdiction source for
#: bundles enriched before :attr:`IPInfo.asn_country` existed.
_ASN_COUNTRY_SUFFIX_RE = re.compile(r",\s*([A-Z]{2})\s*$")


def _jurisdiction_cc(ip) -> str:
    """Return the ASN registration country for ``ip`` (the jurisdiction axis).

    Prefers the dedicated ``asn_country`` field (populated at enrichment
    from Team Cymru); falls back to the trailing ``", CC"`` Cymru appends to
    ``as_org`` so bundles enriched before that field existed still score.
    """
    if getattr(ip, "asn_country", ""):
        return ip.asn_country
    m = _ASN_COUNTRY_SUFFIX_RE.search(ip.as_org or "")
    return m.group(1) if m else ""


def _component_ips(dp, component: str) -> list:
    """Return the :class:`IPInfo` records backing one infrastructure component.

    ``component`` is ``"host"`` (A/AAAA), ``"mail"`` (MX host IPs), or
    ``"dns"`` (nameserver IPs).
    """
    if component == "host":
        return list(dp.a_records or []) + list(dp.aaaa_records or [])
    if component == "mail":
        return [ip for h in (dp.mx or []) for ip in (h.ips or [])]
    if component == "dns":
        return [ip for n in (dp.nameservers or []) for ip in (n.ips or [])]
    return []


def _add_sovereignty_signals(dp, add) -> None:
    """Fire the per-component physical / jurisdiction extra-EU signals.

    For each of web host, mail, and DNS, two independent facts are scored:
    the server's physical location (geoip ``country_code``) and its legal
    jurisdiction (ASN registration ``asn_country``). Both axes cumulate,
    and the three components are scored independently.
    """
    for component in ("host", "mail", "dns"):
        ips = _component_ips(dp, component)
        if any(_outside_eu(ip.country_code) for ip in ips):
            add(f"{component}_physical_extra_eu")
        if any(_outside_eu(_jurisdiction_cc(ip)) for ip in ips):
            add(f"{component}_jurisdiction_extra_eu")


def _cookie_hygiene_ok(analysis) -> bool:
    """``False`` when an operator ``Set-Cookie`` is ``SameSite=None`` without
    ``Secure``. Empty / jar-only cookies pass (nothing the operator emits)."""
    for cookie in analysis.cookies or []:
        if getattr(cookie, "source", "set-cookie") != "set-cookie":
            continue
        same_site = (getattr(cookie, "same_site", "") or "").lower()
        if same_site == "none" and not getattr(cookie, "secure", False):
            return False
    return True


def _hsts_present(headers: dict[str, str] | None) -> bool:
    """``True`` when HSTS is set with a positive ``max-age`` (``max-age=0``
    is explicit disablement; absent headers can't be certified)."""
    if not headers:
        return False
    value = headers.get("strict-transport-security")
    if not value:
        return False
    for directive in value.split(";"):
        name, _, raw = directive.strip().partition("=")
        if name.strip().lower() == "max-age":
            try:
                return int(raw.strip()) > 0
            except ValueError:
                return False
    return False


def _csp_present(headers: dict[str, str] | None) -> bool:
    """``True`` when an enforcing CSP is set (report-only does not count)."""
    if not headers:
        return False
    return bool(headers.get("content-security-policy"))


def _xcto_present(headers: dict[str, str] | None) -> bool:
    """``True`` when ``X-Content-Type-Options`` is ``nosniff``."""
    if not headers:
        return False
    return (headers.get("x-content-type-options") or "").strip().lower() == "nosniff"


def _xfo_present(headers: dict[str, str] | None) -> bool:
    """``True`` when ``X-Frame-Options`` is ``DENY`` / ``SAMEORIGIN`` (the
    deprecated ``ALLOW-FROM`` offers no protection and fails)."""
    if not headers:
        return False
    return (headers.get("x-frame-options") or "").strip().upper() in {
        "DENY", "SAMEORIGIN",
    }


def _referrer_policy_present(headers: dict[str, str] | None) -> bool:
    """``True`` when ``Referrer-Policy`` is set and not ``unsafe-url``."""
    if not headers:
        return False
    value = (headers.get("referrer-policy") or "").strip().lower()
    return bool(value) and value != "unsafe-url"


def _permissions_policy_present(headers: dict[str, str] | None) -> bool:
    """``True`` when a non-empty ``Permissions-Policy`` header is set."""
    if not headers:
        return False
    return bool((headers.get("permissions-policy") or "").strip())


@dataclass(frozen=True)
class HeaderCheck:
    """One security-response-header evaluation, sized for the report.

    ``key`` is the lowercased header name, ``label`` its human form,
    ``ok`` whether it is *acceptably* present (decided by the same
    predicate the score keys on — not mere presence), and ``value`` the
    raw observed value (``""`` when the header is absent).
    """

    key: str
    label: str
    ok: bool
    value: str


#: The security headers the report evaluates, in display order, each
#: paired with its scoring predicate — the single source of truth shared
#: by the ``*_missing`` deductions and the rendered "Security headers"
#: section, so the two can never disagree.
_SECURITY_HEADER_CHECKS: tuple[tuple[str, str, object], ...] = (
    ("content-security-policy", "Content-Security-Policy", _csp_present),
    ("strict-transport-security", "Strict-Transport-Security (HSTS)",
     _hsts_present),
    ("x-content-type-options", "X-Content-Type-Options", _xcto_present),
    ("x-frame-options", "X-Frame-Options", _xfo_present),
    ("referrer-policy", "Referrer-Policy", _referrer_policy_present),
    ("permissions-policy", "Permissions-Policy", _permissions_policy_present),
)


def evaluate_security_headers(
    headers: dict[str, str] | None,
) -> list[HeaderCheck] | None:
    """Evaluate the captured main-document headers for the report.

    Returns ``None`` when no document response was observed (the caller
    stays silent — distinct from "observed, none present", which returns
    six :class:`HeaderCheck`s all marked absent). Reuses the scoring
    predicates so the rendered section agrees with the deductions.
    """
    if headers is None:
        return None
    return [
        HeaderCheck(
            key=key, label=label, ok=predicate(headers),
            value=(headers.get(key) or "").strip(),
        )
        for key, label, predicate in _SECURITY_HEADER_CHECKS
    ]


def _persistent_xs_tracking_cookies(analysis) -> list:
    """Third-party, ``SameSite=None``, lifetime-over-threshold cookies."""
    out = []
    for cookie in analysis.cookies or []:
        if getattr(cookie, "is_first_party", True):
            continue
        if (getattr(cookie, "lifetime_days", 0) or 0) <= _PERSISTENT_COOKIE_DAYS_THRESHOLD:
            continue
        if (getattr(cookie, "same_site", "") or "").lower() != "none":
            continue
        out.append(cookie)
    return out


def _forwarded_vendor_module_ids(analysis) -> set[str]:
    """``module_id`` set of vendors using a forwarding/cloaking technique."""
    out: set[str] = set()
    for hit in analysis.hits:
        if _cloak_or_proxy_marked(hit):
            out.add(_FORWARDING_BRIDGE.get(hit.module_id, hit.module_id))
    return out


def forwarded_tracking_cookies(analysis) -> list:
    """First-party tracker cookies whose vendor forwards/cloaks here — the
    identifier still reaches the third party, so "first-party" is a
    disguise. Persistence-only gate (the forwarded reach doesn't depend on
    ``SameSite``)."""
    forwarded = _forwarded_vendor_module_ids(analysis)
    if not forwarded:
        return []
    out = []
    for cookie in analysis.cookies or []:
        module_id = getattr(cookie, "tracker_module_id", "")
        if not module_id or module_id not in forwarded:
            continue
        if (getattr(cookie, "lifetime_days", 0) or 0) <= _PERSISTENT_COOKIE_DAYS_THRESHOLD:
            continue
        out.append(cookie)
    return out


def youtube_embed_cookie_count(analysis) -> int:
    """Persistent cross-site cookies set by a YouTube embed, ``0`` when the
    persistent cookies come from anything else too (then the generic
    cookie advice fits better than the youtube-nocookie one-step fix)."""
    cookies = _persistent_xs_tracking_cookies(analysis)
    if not cookies:
        return 0
    if all(getattr(c, "vendor", "") == _YOUTUBE_EMBED_VENDOR for c in cookies):
        return len(cookies)
    return 0


#: A per-domain penalty above this gets an explainer string (authored
#: in the module / signal). Penalties of 1.0 or less are "minor" and
#: stand on the label alone.
EXPLAINER_THRESHOLD = 1.0


@dataclass(frozen=True)
class Deduction:
    """One fired rating: a module or signal that costs points.

    ``notes`` maps a domain (``"privacy"`` / ``"security"`` /
    ``"resilience"``) to a short explainer of *why* this source costs
    that much on that domain — authored in the module's ``impact_notes``
    or the signal's ``explainers``. Only domains whose impact exceeds
    :data:`EXPLAINER_THRESHOLD` are expected to carry one.
    """

    source_id: str    # module_id or signal_id
    label: str        # human label for rationale lines
    kind: str         # "module" | "signal"
    rating: ImpactRating
    notes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class DeductionLine:
    """One contributor to a dimension: its label, the points it cost,
    and (for penalties over :data:`EXPLAINER_THRESHOLD`) why."""

    label: str
    amount: float
    explainer: str = ""


def _contributions(domain: str, deductions: list) -> list[DeductionLine]:
    """The non-zero contributors to one domain, largest first.

    Carries each source's per-domain explainer (empty when the source
    declares none); the renderer surfaces it only past
    :data:`EXPLAINER_THRESHOLD`.
    """
    lines = [
        DeductionLine(
            label=d.label,
            amount=getattr(d.rating, domain),
            explainer=(d.notes or {}).get(domain, ""),
        )
        for d in deductions
        if getattr(d.rating, domain) > 0
    ]
    lines.sort(key=lambda line: (-line.amount, line.label))
    return lines


@dataclass(frozen=True)
class DimensionResult:
    """One dimension after cumulative deduction and caps.

    ``deductions`` lists the contributors to *this* dimension —
    ``(label, amount)``, largest first, zero-impact entries omitted —
    so rationale lines can name what cost the points. ``cap`` is the
    binding ceiling ``(value, reason)`` when one actually bound,
    ``None`` otherwise.
    """

    domain: str
    stars: float
    deductions: tuple[DeductionLine, ...] = ()
    cap: Cap | None = None


@dataclass(frozen=True)
class ScoreV2:
    """The three deduction-scored dimensions + geometric-mean total."""

    privacy: DimensionResult
    security: DimensionResult
    resilience: DimensionResult
    total: int = field(init=False)

    def __post_init__(self) -> None:
        product = (
            self.privacy.stars * self.security.stars * self.resilience.stars
        )
        total = 0 if product == 0 else round((product ** (1 / 3)) * 10)
        object.__setattr__(self, "total", total)


def _effective_rating(module, module_hits) -> ImpactRating | None:
    """The module's per-capture rating: the variant hook when present
    (Phase 5), else the base ``impact_rating``. The fallback keeps
    rating-only stand-ins (and any module predating the hook) working.
    """
    if module is None:
        return None
    hook = getattr(module, "effective_rating", None)
    if callable(hook):
        return hook(module_hits)
    return getattr(module, "impact_rating", None)


#: Privacy / security cap for EU public-sector collaboration. A public
#: cooperative / government platform still receives the visitor (IP /
#: Referer) and may ship script, so the surface isn't zero — but it is
#: thin and benign, so it is trimmed to this floor rather than scored
#: like a commercial third party.
_PUBLIC_SECTOR_PII_SEC_CAP = 0.5


def _public_sector_adjusted(module, rating: ImpactRating) -> ImpactRating:
    """Apply the EU public-sector leniency to a module's rating.

    Leaning on a Belgian/EU public-sector platform (a municipal
    cooperative, a public vzw, a regional government's own platform) is a
    sovereignty *gain*, not an operational dependency — so for
    ``government`` / ``para_government`` modules whose legal jurisdiction
    is EU/EEA, the **resilience** impact is waived entirely and the
    **privacy / security** impact is trimmed to a thin floor. Every other
    module (and any public-sector module booked outside the EU) is
    returned unchanged. No bonus is applied — the engine is
    deduction-only.
    """
    # Lazy imports: the module-kind constants live in the modules package
    # and EU_MEMBERS in the sibling builder, both of which can import the
    # report layer — deferring here keeps the import graph acyclic.
    from ..modules.base import (
        MODULE_KIND_GOVERNMENT,
        MODULE_KIND_PARA_GOVERNMENT,
    )
    from .builder import EU_MEMBERS

    kind = getattr(module, "module_kind", "")
    if kind not in (MODULE_KIND_GOVERNMENT, MODULE_KIND_PARA_GOVERNMENT):
        return rating
    juris = (getattr(module, "legal_jurisdiction", "") or "").strip().upper()
    if juris != "EU" and juris not in EU_MEMBERS:
        return rating
    return ImpactRating(
        privacy=min(rating.privacy, _PUBLIC_SECTOR_PII_SEC_CAP),
        security=min(rating.security, _PUBLIC_SECTOR_PII_SEC_CAP),
        resilience=0.0,
    )


def module_deductions(
    hits,
    modules_by_id,
) -> tuple[list[Deduction], list[str]]:
    """Build module deduction rows from fired hits.

    ``hits`` is any iterable of objects carrying ``module_id``;
    ``modules_by_id`` maps ids to registered module instances. Each
    distinct module deducts **once** no matter how many hits it
    produced (one embed decision = one deduction), and each *product*
    counts separately even within one vendor. The rating is the
    module's :meth:`effective_rating` over *its own* hits, so a
    per-capture variant (e.g. GA4 with Consent Mode denied) is what
    deducts.

    Returns ``(deductions, unrated_ids)`` — modules without an
    :class:`ImpactRating` (or ids missing from the registry) deduct
    nothing but are named, in first-seen order, so coverage gaps stay
    visible instead of scoring as harmless.
    """
    hits_by_module: dict[str, list] = {}
    order: list[str] = []
    for hit in hits:
        module_id = hit.module_id
        if module_id not in hits_by_module:
            hits_by_module[module_id] = []
            order.append(module_id)
        hits_by_module[module_id].append(hit)

    deductions: list[Deduction] = []
    unrated: list[str] = []
    for module_id in order:
        module = modules_by_id.get(module_id)
        rating = _effective_rating(module, hits_by_module[module_id])
        if rating is None:
            unrated.append(module_id)
            continue
        rating = _public_sector_adjusted(module, rating)
        deductions.append(Deduction(
            source_id=module_id,
            label=module.module_name,
            kind="module",
            rating=rating,
            notes=dict(getattr(module, "impact_notes", {}) or {}),
        ))
    return deductions, unrated


def _compute_dimension(
    domain: str,
    deductions: list[Deduction],
    caps: list[Cap],
) -> DimensionResult:
    """Cumulative deduction for one domain, floored at 0, then capped."""
    contributions = _contributions(domain, deductions)
    stars = max(0.0, 10.0 - sum(line.amount for line in contributions))
    binding: Cap | None = None
    for cap in sorted(caps, key=lambda c: c[0]):
        if cap[0] < stars:
            stars = cap[0]
            binding = cap
        break  # caps sorted ascending: only the tightest can bind
    return DimensionResult(
        domain=domain,
        stars=stars,
        deductions=tuple(contributions),
        cap=binding,
    )


def compute_score_v2(
    deductions,
    *,
    privacy_caps: list[Cap] | None = None,
    security_caps: list[Cap] | None = None,
    resilience_caps: list[Cap] | None = None,
) -> ScoreV2:
    """Score a capture from its fired :class:`Deduction` rows.

    ``deductions`` is the combined module + signal list (build module
    rows via :func:`module_deductions`; signal rows are constructed by
    their emitters). The per-dimension caps keep the v1 ceiling
    semantics: applied after the deduction result, lower-only,
    tightest wins.
    """
    deductions = list(deductions)
    return ScoreV2(
        privacy=_compute_dimension(
            "privacy", deductions, privacy_caps or [],
        ),
        security=_compute_dimension(
            "security", deductions, security_caps or [],
        ),
        resilience=_compute_dimension(
            "resilience", deductions, resilience_caps or [],
        ),
    )


# ---------------------------------------------------------------------------
# Deduction assembler: one Analysis -> the full Deduction list
# ---------------------------------------------------------------------------


def _signal_deductions(analysis) -> list[Deduction]:
    """Map an Analysis's adverse facts to non-module signal deductions.

    Reuses the v1 predicate library (lazy-imported to avoid an
    import-time cycle) and the Phase-4 signal catalog. The certainty
    rule governs every posture signal: it fires only when the
    underlying data is **present and adverse** — an un-enriched bundle
    (no transport / DNS / headers / security.txt) is never penalised
    for data that was never measured. Cookie and consent signals fire
    once per offending *vendor* so they cumulate (and the vendor name
    rides on the label for the rationale).

    Dedup of the cookie/consent signals against the vendor modules that
    set them, and whether the consent / EOL signals apply as deductions
    or as the v1 caps, are Phase-6 *calibration* decisions — this
    assembler emits the raw signal rows; the policy is decided on real
    numbers downstream.
    """
    from ..signals import SIGNAL_CATALOG

    out: list[Deduction] = []

    def add(signal_id: str, label: str | None = None) -> None:
        entry = SIGNAL_CATALOG[signal_id]
        out.append(Deduction(
            source_id=signal_id, label=label or entry.label,
            kind="signal", rating=entry.rating, notes=entry.explainers,
        ))

    tp = getattr(analysis, "transport_posture", None)
    sh = getattr(analysis, "security_headers", None)
    dp = getattr(analysis, "dns_posture", None)
    tls = getattr(analysis, "tls_posture", None)

    # Transport (only when probed).
    if tp is not None:
        if not tp.primary.https_responded:
            add("https_broken")
        elif not tp.primary.http_redirects_to_https:
            add("no_https_redirect")

    # TLS quality (only when the handshake reached the TLS layer). The
    # certain-data rule governs: an invalid chain dominates (no expiry
    # double-count), a deprecated protocol fires only on a confirmed
    # acceptance, and near-expiry applies only to an otherwise-valid cert.
    if tls is not None and getattr(tls, "connected", False):
        if tls.verify_error:
            add("tls_cert_invalid")
        else:
            if "accepted" in (tls.legacy_tls10, tls.legacy_tls11):
                add("tls_legacy_protocol")
            if tls.days_until_expiry is not None \
                    and 0 <= tls.days_until_expiry <= CERT_EXPIRY_WARN_DAYS:
                add("tls_cert_expiring_soon")

    # Response headers (only when the landing response was observed).
    if sh is not None:
        if not _hsts_present(sh):
            add("hsts_missing")
        if not _csp_present(sh):
            add("csp_missing")
        if not _xcto_present(sh):
            add("xcto_missing")
        if not _xfo_present(sh):
            add("xfo_missing")
        if not _referrer_policy_present(sh):
            add("referrer_policy_missing")
        if not _permissions_policy_present(sh):
            add("permissions_policy_missing")

    # DNS / mail posture (only when DNS was looked up).
    if dp is not None:
        signed = bool(dp.dnssec and dp.dnssec.parent_has_ds
                      and dp.dnssec.zone_has_dnskey)
        if not signed:
            add("dnssec_unsigned")
        strict = bool(dp.dmarc and (dp.dmarc.policy or "").lower()
                      in _DMARC_STRICT_POLICIES)
        if not strict:
            add("dmarc_weak")
        spf_ok = bool(dp.spf and (dp.spf.final_qualifier or "")
                      in _SPF_ACCEPTABLE_QUALIFIERS)
        if not spf_ok:
            add("spf_weak")
        if not (dp.caa and dp.caa.raw_records):
            add("caa_missing")
        # MTA-STS is an inbound-SMTP control: only relevant when the domain
        # actually receives mail (publishes an MX). A no-mail domain is not
        # penalised for lacking it.
        if dp.mx and not (dp.mta_sts and dp.mta_sts.txt_present):
            add("mta_sts_missing")
        # Exactly one authoritative nameserver is a resolution SPOF; zero
        # means the lookup did not resolve (never scored).
        if len(dp.nameservers) == 1:
            add("dns_single_nameserver")
        if not dp.aaaa_records:
            add("no_ipv6")

    # Operator cookie hygiene (data-driven; only fails on a real bad cookie).
    if not _cookie_hygiene_ok(analysis):
        add("cookie_hygiene_bad")

    # End-of-life platform (the judged fingerprint, stamped by the builder).
    fp = getattr(analysis, "cms_fingerprint", None)
    if fp is not None and getattr(fp, "is_eol", False):
        add("eol_platform")

    # Server sovereignty: physical location + legal jurisdiction outside the
    # EU, per infrastructure component (web host / mail / DNS).
    if dp is not None:
        _add_sovereignty_signals(dp, add)

    # Missing SRI — once per distinct third-party host, split by kind.
    missing = getattr(analysis, "missing_sri", None) or []
    script_hosts = sorted({
        m.host for m in missing if getattr(m, "kind", "script") == "script"
    })
    sheet_hosts = sorted({
        m.host for m in missing if getattr(m, "kind", "script") == "stylesheet"
    })
    for host in script_hosts:
        add("missing_sri_script", f"Third-party script without SRI: {host}")
    for host in sheet_hosts:
        add("missing_sri_stylesheet",
            f"Third-party stylesheet without SRI: {host}")

    # security.txt (only when the probe ran).
    st = getattr(analysis, "security_txt", None)
    if st is not None and not getattr(st, "found", False):
        add("security_txt_missing")

    # Persistent cross-site cookies — once per distinct setting vendor.
    persistent = _persistent_xs_tracking_cookies(analysis)
    for vendor in sorted({
        (getattr(c, "vendor", "") or getattr(c, "host", "") or "?")
        for c in persistent
    }):
        add("persistent_xs_cookie", f"Persistent cross-site cookie: {vendor}")

    # Forwarded (cloaked) first-party cookies — once per distinct vendor.
    for vendor in sorted({
        (getattr(c, "vendor", "") or "?")
        for c in forwarded_tracking_cookies(analysis)
    }):
        add("forwarded_tracking_cookie",
            f"Forwarded first-party cookie: {vendor}")

    # Consent compliance — once per offending vendor.
    consent = getattr(analysis, "consent", None)
    if consent is not None:
        for vendor in consent.pre_decision_vendors:
            add("pre_consent_tracking", f"Tracking before consent: {vendor}")
        for vendor in consent.post_reject_vendors:
            add("post_reject_tracking", f"Tracking after reject: {vendor}")

    return out


def build_deductions(
    analysis, modules_by_id,
) -> tuple[list[Deduction], list[str]]:
    """Assemble every :class:`Deduction` for one capture.

    Combines the module deductions (each module's
    :meth:`~leak_inspector.modules.base.TrackerModule.effective_rating`
    over its own hits, so per-capture variants apply) with the
    non-module signal deductions mapped from the analysis facts. Returns
    ``(deductions, unrated_module_ids)`` — the unrated list surfaces any
    fired module still missing a triple.
    """
    module_rows, unrated = module_deductions(
        getattr(analysis, "hits", []), modules_by_id,
    )
    return module_rows + _signal_deductions(analysis), unrated


# ---------------------------------------------------------------------------
# Logistic dimension scoring (calibration model)
# ---------------------------------------------------------------------------
#
# An alternative to the linear-floor dimension above: map each
# dimension's summed penalty through a logistic (S-curve) so that both
# perfection (100) and rock-bottom (0) are *asymptotes* — the closer a
# dimension gets to either, the less a further penalty moves it, and the
# steepest response is in the middle. The three 0–100 dimension scores
# are then combined by the same cube-root (geometric mean) the linear
# model uses for the total.
#
#     score(P) = 100 / (1 + e^((P − p50) / s))
#
# ``p50`` is the penalty that yields 50; ``s`` is the steepness (smaller
# = sharper middle). A penalty-free dimension scores
# ``100 / (1 + e^(−p50/s))`` — just under 100 (perfection is an
# asymptote, never exactly reached).
#
# Calibrated against the real municipalities corpus. p50=11 / s=5 makes
# the curve both more demanding and less steep than the original
# 14 / 3.5: the penalty-free anchor sits at ~90 (so even a clean site
# tops out around 90, not 98), a site with a few issues lands mid-high
# (izegem ~75) and a moderately tracker-heavy one sits mid-low
# (woluwe1150 ~40), while the worst still bottom out near 0. The wider s
# spreads the middle of the distribution instead of saturating it near
# 100. Re-run ``tools/score_v2_preview.py`` to retune.

#: Logistic parameters (penalty that scores 50; steepness).
DEFAULT_P50: float = 11.0
DEFAULT_S: float = 5.0


@dataclass(frozen=True)
class LogisticDimension:
    """One dimension scored by the logistic curve (0–100, never clamped).

    ``penalty`` is the raw summed impact on this domain; ``score`` is
    that penalty mapped through the curve; ``deductions`` lists the
    contributors ``(label, amount)`` largest-first (zero-impact
    omitted), as in :class:`DimensionResult`.
    """

    domain: str
    penalty: float
    score: float
    deductions: tuple[DeductionLine, ...] = ()


@dataclass(frozen=True)
class LogisticScore:
    """The three logistic dimensions + their cube-root total (all 0–100)."""

    privacy: LogisticDimension
    security: LogisticDimension
    resilience: LogisticDimension
    p50: float
    s: float
    total: float = field(init=False)

    def __post_init__(self) -> None:
        product = self.privacy.score * self.security.score * self.resilience.score
        total = product ** (1 / 3) if product > 0 else 0.0
        object.__setattr__(self, "total", total)


def logistic_score(penalty: float, *, p50: float, s: float) -> float:
    """Map a non-negative ``penalty`` to a 0–100 score via the S-curve.

    Monotonically decreasing; asymptotic to 100 as ``penalty → 0`` and
    to 0 as ``penalty → ∞``; equals 50 at ``penalty == p50``. Overflow-
    safe at the tails.
    """
    z = (penalty - p50) / s
    if z > 700:        # e^z overflows; the score is 0 to many decimals
        return 0.0
    if z < -700:
        return 100.0
    return 100.0 / (1.0 + math.exp(z))


def _logistic_dimension(
    domain: str, deductions: list[Deduction], *, p50: float, s: float
) -> LogisticDimension:
    contributions = _contributions(domain, deductions)
    penalty = sum(line.amount for line in contributions)
    return LogisticDimension(
        domain=domain,
        penalty=penalty,
        score=logistic_score(penalty, p50=p50, s=s),
        deductions=tuple(contributions),
    )


def compute_score_logistic(
    deductions,
    *,
    p50: float = DEFAULT_P50,
    s: float = DEFAULT_S,
) -> LogisticScore:
    """Score a capture's :class:`Deduction` rows via the logistic model.

    Each dimension's summed penalty is mapped through the S-curve to a
    0–100 score (no floor, no cap — the curve handles both ends); the
    total is the cube-root (geometric mean) of the three, matching the
    linear model's combine. ``p50`` / ``s`` tune the curve.
    """
    deductions = list(deductions)
    return LogisticScore(
        privacy=_logistic_dimension("privacy", deductions, p50=p50, s=s),
        security=_logistic_dimension("security", deductions, p50=p50, s=s),
        resilience=_logistic_dimension("resilience", deductions, p50=p50, s=s),
        p50=p50,
        s=s,
    )


# ---------------------------------------------------------------------------
# Presentation adapter: a report-facing view of the logistic score
# ---------------------------------------------------------------------------
#
# The renderers (text / markdown / html) and the bulk overview all
# duck-type the same score interface: ``score.total`` / ``max_total``,
# ``score.<dim>.stars`` / ``max_stars`` / ``rationale``, and
# ``score.top_action``. ScoreView reproduces that interface over the
# logistic result — ``stars`` now on a 0–100 scale, ``max_stars`` = 100
# — so the scorecard shows 0–100 per dimension with no renderer change.


@dataclass(frozen=True)
class DimensionView:
    """One dimension, report-facing. ``stars`` is the displayed 0–100
    score (ceil of ``raw_score``); the attribute name is kept for
    renderer compatibility. ``raw_score`` is the un-ceiled logistic
    value, exposed so the report can show the exact derivation."""

    stars: float
    max_stars: int
    rationale: str
    penalty: float
    deductions: tuple[DeductionLine, ...]
    raw_score: float = 0.0


@dataclass(frozen=True)
class ScoreView:
    """Report-facing v2 score: three 0–100 dimensions + a 0–100 total.

    ``total`` is the displayed integer (ceil of the raw logistic total);
    ``raw_total`` is that un-ceiled float, carried so consumers can order
    sites that share a displayed score by their true underlying value
    (the rendered number is the same, but the ranking is exact). Defaults
    to ``0.0`` for older callers that construct a view directly.
    """

    resilience: DimensionView
    security: DimensionView
    privacy: DimensionView
    total: int
    max_total: int
    top_action: str | None
    raw_total: float = 0.0


def _dimension_rationale(dim: LogisticDimension) -> str:
    """Name the heaviest deductions on a dimension, top-three then a
    ``+N more`` tail (or ``"no penalties"`` when clean)."""
    if not dim.deductions:
        return "no penalties"
    shown = ", ".join(
        f"{line.label} −{line.amount:g}" for line in dim.deductions[:3]
    )
    extra = len(dim.deductions) - 3
    return shown + (f", +{extra} more" if extra > 0 else "")


def _top_action(deductions: list[Deduction]) -> str | None:
    """The biggest win: the deduction with the largest **total** impact
    summed across the three domains — so a module that hits two or three
    domains outranks one with a bigger single-domain hit but a smaller
    footprint. The displayed cost reflects that total (with the per-domain
    breakdown when more than one domain is affected), rather than a single
    domain, so the choice doesn't read as a one-dimension pick.
    """
    if not deductions:
        return None
    worst = max(deductions, key=lambda d: (
        d.rating.privacy + d.rating.security + d.rating.resilience,
        d.label,
    ))
    # Affected domains, biggest first; drop the ones the module doesn't touch.
    by_domain = sorted(
        (("privacy", worst.rating.privacy),
         ("resilience", worst.rating.resilience),
         ("security", worst.rating.security)),
        key=lambda pair: -pair[1],
    )
    affected = [(dom, amt) for dom, amt in by_domain if amt > 0]
    prefix = "Remove or replace" if worst.kind == "module" else "Address:"
    if not affected:
        return None
    if len(affected) == 1:
        dom, amt = affected[0]
        cost = f"−{amt:g} {dom}"
    else:
        total = sum(amt for _, amt in affected)
        breakdown = ", ".join(f"{dom} {amt:g}" for dom, amt in affected)
        cost = f"−{total:g} total: {breakdown}"
    return f"{prefix} {worst.label} ({cost})"


def _display(score: float) -> int:
    """Round a 0–100 logistic score *up* (ceil) to its displayed integer.

    The curve is asymptotic at both ends, and ceil reflects that in the
    printed number: any positive raw score ceils to ≥ 1 (so 0 is never
    printed), and the penalty-free anchor (~90.0) ceils to 91 (so 100 —
    true perfection — is never printed either)."""
    return math.ceil(score) if score > 0 else 0


def _dimension_view(dim: LogisticDimension) -> DimensionView:
    return DimensionView(
        stars=_display(dim.score),
        max_stars=100,
        rationale=_dimension_rationale(dim),
        penalty=dim.penalty,
        deductions=dim.deductions,
        raw_score=dim.score,
    )


def build_score_view(
    analysis,
    modules_by_id,
    *,
    p50: float = DEFAULT_P50,
    s: float = DEFAULT_S,
) -> ScoreView | None:
    """Build the report-facing v2 score for one capture.

    Assembles the deductions, scores them through the logistic model,
    and adapts the result to the renderer/bulk interface (0–100
    dimensions + total, rationale strings naming the top deductions, and
    a biggest-win top action).

    Returns ``None`` when the posture data needed to score honestly is
    absent (no transport *or* no DNS posture — an un-enriched bundle):
    scoring it would credit security/resilience we never measured. The
    report then says "not enough data to score" instead, mirroring the
    v1 gate.
    """
    if (getattr(analysis, "transport_posture", None) is None
            or getattr(analysis, "dns_posture", None) is None):
        return None
    deductions, _unrated = build_deductions(analysis, modules_by_id)
    logistic = compute_score_logistic(deductions, p50=p50, s=s)
    return ScoreView(
        resilience=_dimension_view(logistic.resilience),
        security=_dimension_view(logistic.security),
        privacy=_dimension_view(logistic.privacy),
        total=_display(logistic.total),
        max_total=100,
        top_action=_top_action(deductions),
        raw_total=logistic.total,
    )


__all__ = [
    "DOMAINS",
    "DEFAULT_P50",
    "DEFAULT_S",
    "HeaderCheck",
    "evaluate_security_headers",
    "DimensionView",
    "ScoreView",
    "build_score_view",
    "Deduction",
    "DimensionResult",
    "LogisticDimension",
    "LogisticScore",
    "ScoreV2",
    "build_deductions",
    "compute_score_logistic",
    "compute_score_v2",
    "logistic_score",
    "module_deductions",
]
