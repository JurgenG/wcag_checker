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

"""Canonical report-document schema.

A :class:`ReportDocument` is the single source of truth that every
output format renders. The flow is::

    Analysis  ─►  build_report_document(...)  ─►  ReportDocument
                                                      ├──► JSON reporter
                                                      ├──► text reporter
                                                      ├──► markdown reporter
                                                      └──► HTML reporter

Each renderer becomes a thin walk over the document tree; the *what*
of the report (findings, rollups, jurisdictions, per-tracker drill-
downs) lives here, while the *how* (ANSI codes, markdown bullet
syntax, HTML markup + CSS) stays in the renderer.

Schema decisions:

* Every field that ends up in JSON is JSON-native (str / int / bool /
  list / dict). No tuples — they round-trip badly through asdict and
  json.dumps treats them as lists anyway.
* Tooltip text (vendor sovereignty, field meaning, category
  description) is pre-built in the builder so renderers don't need
  module-meta access.
* Display affordances like emoji flags and severity badges are
  rendered into strings here, not generated per-renderer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Renderer-facing data types for the DNS-posture section. The
#: producer (:mod:`leak_inspector.dns_posture`) owns the dataclass
#: definitions; we re-export them here so every renderer imports
#: *every* data type it needs from a single module — keeping reporters
#: structurally identical and decoupled from producer packages.
from ..dns_posture import (
    BIMIRecord,
    CAARecord,
    DKIMSelector,
    DMARCRecord,
    DNSPosture,
    DNSSECStatus,
    HostRecord,
    HTTPSRecord,
    IPInfo,
    MTASTSStatus,
    NameserverRecord,
    SPFRecord,
    TLSRPTStatus,
    TXTVerification,
)

#: Bumped when the on-disk JSON shape changes incompatibly. v1 was the
#: pre-document `{manifest, hits, representatives, untracked_hosts?}`
#: shape; v2 added the executive-summary tree; v3 added
#: :attr:`ReportDocument.dns_posture`; v4 added
#: :attr:`ReportDocument.score` (the composite scorecard); v5
#: restructured score: per-dimension scale 0-10, geometric-mean
#: aggregation, sovereignty renamed to resilience.
SCHEMA_VERSION = 5


# ---------------------------------------------------------------------------
# Generic building blocks
# ---------------------------------------------------------------------------


@dataclass
class FieldRef:
    """One parameter key surfaced in the per-vendor HIGH-impact rollup.

    The ``meaning`` is the human-readable explanation the renderer puts
    into a tooltip (HTML) or omits (text).
    """

    key: str
    meaning: str = ""


@dataclass
class CategoryGroup:
    """A category bucket of fields shown under one vendor rollup.

    ``description`` is the one-sentence explanation of what the
    category represents — used as the category-label tooltip in HTML.
    """

    category: str
    description: str = ""
    fields: list[FieldRef] = field(default_factory=list)


@dataclass
class ModuleRef:
    """One module entry inside a vendor's ``[module1, module2, …]`` bracket.

    ``tooltip`` carries the module's sovereignty metadata as a one-line
    string (vendor + jurisdiction + residency + notes), built once by
    the builder.
    """

    name: str
    tooltip: str = ""


# ---------------------------------------------------------------------------
# Executive-summary atoms
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """One actionable observation surfaced in the executive summary.

    ``severity`` is one of ``"high"`` / ``"medium"`` / ``"low"``
    (matches the existing IMPACT_* constants). ``badge`` is the
    pre-rendered emoji indicator the renderer can drop in directly.

    ``kind`` is a stable slug (``"dmarc_p_none"``,
    ``"transport_https_missing"``, ...) used by the verdict layer's
    action-metadata map to attach owner + effort hints. Empty by
    default — finding-emitters that have no metadata to attach can
    leave it untouched.
    """

    severity: str
    badge: str
    headline: str
    detail: str = ""
    action: str = ""
    kind: str = ""
    #: Where this finding came from. ``"capture"`` (default) for
    #: anything derived from the live browsing session — trackers,
    #: jurisdiction rollups, transport posture, etc. ``"dns"`` for
    #: findings derived from the first-party DNS-posture snapshot
    #: (DMARC, SPF, DKIM, MX, TXT-disclosed SaaS relationships, etc.).
    #: Drives the website-vs-back-office split in the executive summary.
    source: str = "capture"


@dataclass
class CloakRecord:
    """One CNAME-cloaked tracker attribution."""

    alias: str
    canonical: str
    vendor_module_name: str
    module_id: str


@dataclass
class VendorRollup:
    """All HIGH-impact fields one vendor collected, broken down by category."""

    vendor_label: str
    vendor_tooltip: str
    modules: list[ModuleRef] = field(default_factory=list)
    categories: list[CategoryGroup] = field(default_factory=list)
    total_high_impact_fields: int = 0


@dataclass
class JurisdictionTally:
    """One jurisdiction entry in the per-jurisdiction tally."""

    code: str
    flag: str
    is_eu: bool
    module_count: int
    vendors: list[str] = field(default_factory=list)
    background_class: str = ""  # render-helper hint (e.g. "high-risk", "eu", "uk")


@dataclass
class TopByImpactEntry:
    """One row in the "top trackers by impact" rollup."""

    module_id: str
    module_name: str
    high_impact_field_count: int
    medium_impact_field_count: int
    hit_count: int


@dataclass
class SummaryStats:
    """Volume statistics at the bottom of the executive summary."""

    trackers_fired: int
    total_requests: int
    unique_requests: int
    third_party_hosts_touched: int
    third_party_hosts_claimed: int
    third_party_hosts_unclassified: int
    top_by_impact: list[TopByImpactEntry] = field(default_factory=list)


@dataclass
class ExecutiveSummary:
    """The 30-second-read board-level view of the capture."""

    findings: list[Finding] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    cname_cloak_tooltip: str = ""
    cname_cloaks: list[CloakRecord] = field(default_factory=list)
    high_impact_by_vendor: list[VendorRollup] = field(default_factory=list)
    jurisdictions: list[JurisdictionTally] = field(default_factory=list)
    stats: SummaryStats | None = None


# ---------------------------------------------------------------------------
# Per-tracker drill-down
# ---------------------------------------------------------------------------


@dataclass
class ParamRow:
    """One row inside a representative-hit table."""

    key: str
    value: str
    category: str
    privacy_impact: str
    meaning: str = ""


@dataclass
class RepresentativeHit:
    """One deduplicated request the renderer shows under a tracker section."""

    method: str
    url: str
    host: str
    response_status: int | None
    collapsed_event_count: int
    event_ids: list[int] = field(default_factory=list)
    request_body: str | None = None
    response_body: str | None = None
    params: list[ParamRow] = field(default_factory=list)


@dataclass
class HarvestedField:
    """One chip in the per-tracker "Harvested fields" summary block."""

    key: str
    category: str
    count: int


@dataclass
class VendorMeta:
    """Pre-rendered vendor metadata for the per-tracker section header.

    ``flag`` and ``is_eu`` are computed once in the builder so each
    renderer doesn't have to redo the country-to-flag mapping.
    ``tooltip`` is the same vendor-sovereignty string the executive-
    summary rollup uses.
    """

    vendor: str = ""
    legal_jurisdiction: str = ""
    flag: str = ""
    is_eu: bool = False
    data_residency: str = ""
    sovereignty_notes: str = ""
    tooltip: str = ""


@dataclass
class ModuleSection:
    """One per-tracker section in the detailed report."""

    module_id: str
    module_name: str
    vendor_meta: VendorMeta
    total_hits: int
    representative_count: int
    unique_param_keys: int
    category_counts: dict[str, int] = field(default_factory=dict)
    harvested_fields: list[HarvestedField] = field(default_factory=list)
    representative_hits: list[RepresentativeHit] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Unclassified hosts (debug surface)
# ---------------------------------------------------------------------------


@dataclass
class SampleUrl:
    """One sample URL captured for an unclassified host."""

    method: str
    url: str


@dataclass
class UnclassifiedHost:
    """Aggregated info about one third-party host no module claimed."""

    host: str
    count: int
    methods: dict[str, int] = field(default_factory=dict)
    statuses: dict[str, int] = field(default_factory=dict)
    sample_urls: list[SampleUrl] = field(default_factory=list)
    param_samples: dict[str, str] = field(default_factory=dict)
    first_initiator: str | None = None
    first_event_id: int | None = None
    first_timestamp: str | None = None
    #: CDN / edge / vendor-own provider operating this host's CNAME
    #: tail, when one can be identified. Explains "why is this host
    #: unclassified?" — typically because it's first-party hosting
    #: fronted by a CDN.
    cdn_provider: object | None = None


# ---------------------------------------------------------------------------
# Manifest (subset for renderer use; full manifest passed-through in JSON)
# ---------------------------------------------------------------------------


@dataclass
class ManifestView:
    """Manifest fields the renderers use for the header banner.

    The full manifest is still serialized into JSON output as a
    pass-through; this is the renderer-facing convenience copy.
    """

    target_url: str
    landing_url: str
    base_domain: str
    session_id: str
    started_at: str
    ended_at: str
    profile: str
    browser_name: str
    browser_version: str
    raw: dict[str, Any] = field(default_factory=dict)
    #: Optional human label for the report title, overriding the host
    #: (e.g. a site's name from the bulk runner's ``domains.csv``). When
    #: None the report titles itself by ``target_url``'s host.
    display_name: str | None = None


# ---------------------------------------------------------------------------
# Cookies set during the capture
# ---------------------------------------------------------------------------


@dataclass
class CookieEntry:
    """One ``Set-Cookie`` observed during the capture.

    Captures the wire-level metadata the auditor needs to judge
    persistence + cross-site reach:

    * Identity — ``name`` plus the ``host`` that issued the
      ``Set-Cookie`` header. The visitor's first-party domain marks
      ``is_first_party = True``; everything else is a tracking surface.
    * Vendor — the human-readable label of the module that claimed the
      issuing host, or the bare hostname when no module matched (so
      first-party + unclassified-3p cookies still surface).
    * Lifetime — ``max_age_seconds`` (RFC 6265 ``Max-Age`` wins over
      ``Expires``) plus a human label like ``"~30d"`` / ``"session"``
      / ``"~1.2y"`` for the report.
    * Security flags — ``secure`` / ``http_only`` / ``partitioned``
      booleans; ``same_site`` the literal attribute string (lowercase).
    * ``privacy_impact`` — ``"high" | "medium" | "low"`` derived from
      the same rules the per-hit ``(set-cookie)`` ParamInfo uses
      (CHIPS overrides; otherwise ``SameSite=None`` × persistence
      determines the score).
    """

    name: str
    host: str
    vendor: str
    is_first_party: bool
    domain: str = ""              # the Domain= attribute, "" if absent
    path: str = "/"
    max_age_seconds: int | None = None
    lifetime_days: float | None = None
    lifetime_human: str = "session"
    same_site: str = ""           # "lax" | "strict" | "none" | ""
    secure: bool = False
    http_only: bool = False
    partitioned: bool = False
    privacy_impact: str = "low"
    #: How the cookie was observed: ``"set-cookie"`` (a ``Set-Cookie``
    #: response header seen on the wire) or ``"stored"`` (present in the
    #: browser's first-party cookie jar at snapshot time, e.g. set by
    #: JavaScript via ``document.cookie`` — invisible to ``Set-Cookie``).
    source: str = "set-cookie"
    #: ``module_id`` of the tracker that sets this cookie when the name is
    #: a recognised tracker cookie (``_ga`` → ``"ga4"``), else ``""``.
    #: Lets scoring link a first-party cookie back to a forwarding /
    #: cloaking hit for the same vendor.
    tracker_module_id: str = ""


# ---------------------------------------------------------------------------
# Browser storage observed during the capture
# ---------------------------------------------------------------------------


@dataclass
class StorageEntry:
    """One ``localStorage`` / ``sessionStorage`` key observed at session end.

    Bundles already carry per-origin storage snapshots (see
    :mod:`leak_inspector.capture.storage`); analysis collapses them to
    the final state per ``(origin, kind, key)`` so the report shows
    "what the page is storing about the visitor" without surfacing the
    actual values (which routinely contain identifiers, auth tokens,
    or PII).

    Only ``"local"`` and ``"session"`` kinds end up here; the
    ``"cookie"`` snapshot kind is rendered by the cookie overview
    (which carries the lifetime + security-flag metadata
    ``document.cookie`` cannot see).
    """

    origin: str
    kind: str           # "local" | "session"
    key: str
    value_bytes: int    # UTF-8 byte length of the value (size only, never the value)


# ---------------------------------------------------------------------------
# Capture status
# ---------------------------------------------------------------------------


@dataclass
class CaptureStatus:
    """Whether the landing-page load actually succeeded.

    Surfaces three distinct outcomes:

    * **Healthy** — landing-URL request returned a 2xx status (or the
      redirect chain ended cleanly at a 200). ``is_failure`` is False
      and the report renders normally.
    * **HTTP error** — landing-URL request returned 4xx or 5xx.
      ``http_status`` carries the code and ``reason`` carries the
      standard reason phrase (e.g. "I'm a Teapot", "Not Found",
      "Internal Server Error"). ``is_failure`` is True.
    * **Unreachable** — no successful HTTP response was ever received
      for the landing URL. Typically a typo, DNS failure, or
      connection refused. ``http_status`` is None and ``reason`` is
      a short label like "Unreachable". ``is_failure`` is True.

    The bulk-tool overview consumes this to exclude failed captures
    from best/worst rankings (a site that didn't load can't be
    meaningfully ranked) while still listing them in the all-reports
    table with their status surfaced inline.
    """

    http_status: int | None
    reason: str
    is_failure: bool


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------


@dataclass
class ReportDocument:
    """The single source of truth for one capture's analysis output.

    JSON reporter serializes this directly; every other renderer walks
    it. Renderers never touch :class:`Analysis` — once the document is
    built, the analysis can be discarded.
    """

    schema_version: int
    manifest: ManifestView
    executive_summary: ExecutiveSummary
    trackers: list[ModuleSection] = field(default_factory=list)
    unclassified_hosts: list[UnclassifiedHost] = field(default_factory=list)
    #: First-party-domain DNS-posture snapshot from the bundle's stored
    #: enrichment (captured at enrichment time, normally right after the
    #: browsing session). ``None`` when the bundle has no enrichment or
    #: the capture had no base_domain to look up.
    dns_posture: DNSPosture | None = None
    #: When the bundle's enrichment (network posture) was captured —
    #: ISO-8601 UTC. ``None`` when the bundle carries no enrichment;
    #: renderers then say "posture not captured" and point at the
    #: ``leak-inspector enrich`` command.
    enriched_at: str | None = None
    #: Per-section last-probe times (from ``enrich --refresh <section>``),
    #: keyed by canonical section id. Empty when the posture is uniform;
    #: renderers note any section whose time differs from ``enriched_at``.
    section_timestamps: dict[str, str] = field(default_factory=dict)
    #: Reachability classification of the landing-page load. ``None``
    #: only on bundles produced by builds that didn't carry this field.
    capture_status: CaptureStatus | None = None
    #: Every ``Set-Cookie`` observed during the capture, with parsed
    #: lifetime + security-flag metadata. Empty list when no cookies
    #: were set anywhere in the session.
    cookies: list[CookieEntry] = field(default_factory=list)
    #: ``(name, host)`` keys of the entries in :attr:`cookies` whose
    #: vendor uses a forwarding/cloaking technique in this capture
    #: (CNAME cloak / first-party proxy), so the identifier still
    #: reaches the third-party controller. Computed from the hits via
    #: the scoring helper — never stored on the entry, which stays
    #: honestly first-party. Renderers use it to attach a
    #: "(via first-party proxy)" note in the cookie overview.
    forwarded_cookie_keys: list[tuple[str, str]] = field(default_factory=list)
    #: ``localStorage`` / ``sessionStorage`` keys observed across the
    #: session, collapsed to end-of-session state per
    #: ``(origin, kind, key)``. Values are intentionally not carried;
    #: only their UTF-8 byte length.
    storage: list[StorageEntry] = field(default_factory=list)
    #: Best-effort CMS / web-platform fingerprint with EOL judgment
    #: applied. ``None`` when no platform was identified from passive
    #: signals + version probe.
    cms_fingerprint: object | None = None
    #: HTTP/HTTPS transport posture of the captured host (and its
    #: apex/www alternate when applicable). Drives the "Transport
    #: posture" report section plus a derived set of findings folded
    #: into :attr:`ExecutiveSummary.findings`.
    transport_posture: object | None = None
    #: TLS-quality posture of the landing host (certificate validity/
    #: expiry, negotiated protocol, deprecated-protocol acceptance), from
    #: the stored enrichment. Rendered inside the "Transport posture"
    #: section; ``None`` when not probed (renderers stay silent). Actual
    #: type is :class:`leak_inspector.http_posture.tls.TLSPosture`.
    tls_posture: object | None = None
    #: RFC 9116 ``security.txt`` presence probe of the landing host,
    #: from the stored enrichment. ``None`` when not probed (un-enriched
    #: bundle or pre-probe artifact); renderers stay silent then. Actual
    #: type is
    #: :class:`leak_inspector.http_posture.security_txt.SecurityTxtProbe`.
    security_txt: object | None = None
    #: Security response headers of the main document, evaluated for the
    #: report: a list of
    #: :class:`leak_inspector.report.score_v2.HeaderCheck` (one per
    #: canonical header, present-or-absent). ``None`` when no document
    #: response was observed in the capture; renderers stay silent then.
    #: The same presence verdicts the ``*_missing`` score signals key on.
    security_headers: object | None = None
    #: Manager-facing verdict (item 1 of the verdict-layer work).
    #: Grows incrementally as items 2-4 land.
    verdict: object | None = None
    #: Composite sovereignty / security / privacy scorecard (0-100).
    #: ``None`` when posture data is incomplete (hermetic
    #: ``analyze_events`` runs with no transport or DNS lookups).
    #: Type is ``object`` to avoid a circular import with the score
    #: module; the actual type is
    #: :class:`leak_inspector.report.score_v2.ScoreView`.
    score: object | None = None
    #: The session's consent state (decision + pre/post-decision
    #: tracking offenders). ``None`` only when the analysis predates
    #: the consent pass. Type is ``object`` to avoid importing the
    #: analysis layer; actual type is
    #: :class:`leak_inspector.analysis.consent.ConsentState`.
    consent: object | None = None
    #: NIS2 / CCB CyberFundamentals baseline view — the observable
    #: technical controls re-grouped by operator-facing area, each tagged
    #: with its NIS2 Art. 21(2) measure. ``None`` when the bundle carries
    #: no posture data (un-enriched). Type is ``object`` to avoid a
    #: circular import; actual type is
    #: :class:`leak_inspector.report.nis2.CyberFundamentalsView`.
    cyberfundamentals: object | None = None


__all__ = [
    "SCHEMA_VERSION",
    "BIMIRecord",
    "CAARecord",
    "CaptureStatus",
    "CategoryGroup",
    "CookieEntry",
    "StorageEntry",
    "CloakRecord",
    "DKIMSelector",
    "DMARCRecord",
    "DNSPosture",
    "DNSSECStatus",
    "ExecutiveSummary",
    "FieldRef",
    "Finding",
    "HTTPSRecord",
    "HarvestedField",
    "HostRecord",
    "IPInfo",
    "JurisdictionTally",
    "MTASTSStatus",
    "ManifestView",
    "ModuleRef",
    "ModuleSection",
    "NameserverRecord",
    "ParamRow",
    "RepresentativeHit",
    "ReportDocument",
    "SPFRecord",
    "SampleUrl",
    "SummaryStats",
    "TLSRPTStatus",
    "TXTVerification",
    "TopByImpactEntry",
    "UnclassifiedHost",
    "VendorMeta",
    "VendorRollup",
]
