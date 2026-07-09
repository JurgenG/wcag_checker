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

"""Capture-to-capture comparison.

Two ``Analysis`` objects (typically the same site captured twice — e.g.
consent rejected vs accepted) are reduced to a structured
:class:`ReportDiff` that the renderers consume the same way they consume
a single :class:`~leak_inspector.report.document.ReportDocument`.

The diff is a function of two documents: every per-side computation
already exists in :mod:`.builder`, so this module is pure delta logic
plus a small headline summariser.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analysis import Analysis
from ..modules.base import CAT_IDENTIFIER, CAT_PII
from .builder import _canonical_key, build_report_document
from .document import (
    CaptureStatus,
    CookieEntry,
    Finding,
    ManifestView,
    ModuleSection,
    ReportDocument,
    StorageEntry,
)


@dataclass
class ModuleChange:
    """One tracker module that fired on both sides — with field/hit deltas."""

    module_id: str
    module_name: str
    vendor: str
    fields_added: list[str] = field(default_factory=list)
    fields_removed: list[str] = field(default_factory=list)
    hit_count_a: int = 0
    hit_count_b: int = 0


@dataclass(frozen=True)
class PersonalFieldRef:
    """One ``(vendor, category, key)`` triple describing one leaking field."""

    vendor: str
    category: str
    key: str


@dataclass
class PersonalDataDelta:
    """Distinct-field PII/identifier delta between two captures.

    Counts and lists are derived the same way the single-capture
    verdict computes them: dedup per ``(vendor, category, canonical
    key)`` so the same cookie sent on 100 beacons counts once. The
    visitor's actual exposure is the cardinality of these triples.
    """

    count_a: int = 0
    count_b: int = 0
    only_in_a: list[PersonalFieldRef] = field(default_factory=list)
    only_in_b: list[PersonalFieldRef] = field(default_factory=list)


@dataclass
class ReportDiff:
    """The structured delta between two captures of the same (or similar) site."""

    label_a: str
    label_b: str
    manifest_a: ManifestView
    manifest_b: ManifestView
    capture_status_a: CaptureStatus | None
    capture_status_b: CaptureStatus | None
    modules_only_in_a: list[ModuleSection] = field(default_factory=list)
    modules_only_in_b: list[ModuleSection] = field(default_factory=list)
    modules_changed: list[ModuleChange] = field(default_factory=list)
    hosts_only_in_a: list[str] = field(default_factory=list)
    hosts_only_in_b: list[str] = field(default_factory=list)
    findings_only_in_a: list[Finding] = field(default_factory=list)
    findings_only_in_b: list[Finding] = field(default_factory=list)
    new_jurisdictions: list[str] = field(default_factory=list)
    #: Distinct-field PII/identifier delta — what visitor data actually
    #: starts leaking (or stops leaking) between the two captures.
    personal_data_delta: PersonalDataDelta = field(default_factory=PersonalDataDelta)
    #: Cookies present in B but not A (matched by ``(name, host)``).
    #: Typical use: consent-accepted cookies introduced over consent-rejected.
    cookies_added: list[CookieEntry] = field(default_factory=list)
    cookies_removed: list[CookieEntry] = field(default_factory=list)
    #: localStorage / sessionStorage entries unique to one side, matched
    #: by ``(origin, kind, key)``. Values aren't compared (the entry
    #: payload is never carried) — only presence.
    storage_added: list[StorageEntry] = field(default_factory=list)
    storage_removed: list[StorageEntry] = field(default_factory=list)
    #: Plain-language warning when A and B don't look like the same site.
    #: ``None`` when the bundles share a base domain. Renderers should
    #: surface this prominently — diffing two different sites silently
    #: would produce a misleading report.
    bundle_mismatch: str | None = None
    headline: str = ""


# --- public builder --------------------------------------------------------


def build_report_diff(
    analysis_a: Analysis,
    analysis_b: Analysis,
    *,
    label_a: str = "A",
    label_b: str = "B",
) -> ReportDiff:
    """Compute the delta between two captures.

    Each side goes through :func:`build_report_document` independently
    (so the diff sees the same data the single-site reports do); the
    deltas are then walked off the resulting document trees.
    """
    doc_a = build_report_document(analysis_a)
    doc_b = build_report_document(analysis_b)

    modules_only_in_a, modules_only_in_b, modules_changed = _diff_modules(
        doc_a.trackers, doc_b.trackers
    )
    hosts_only_in_a, hosts_only_in_b = _diff_hosts(doc_a.trackers, doc_b.trackers)
    findings_only_in_a, findings_only_in_b = _diff_findings(
        doc_a.executive_summary.findings,
        doc_b.executive_summary.findings,
    )
    new_jurisdictions = _diff_new_jurisdictions(
        doc_a.executive_summary.jurisdictions,
        doc_b.executive_summary.jurisdictions,
    )
    personal_data_delta = _diff_personal_data(analysis_a, analysis_b)
    cookies_added, cookies_removed = _diff_cookies(doc_a.cookies, doc_b.cookies)
    storage_added, storage_removed = _diff_storage(doc_a.storage, doc_b.storage)
    bundle_mismatch = _check_bundle_compat(doc_a.manifest, doc_b.manifest)

    headline = _build_headline(
        label_b=label_b,
        modules_only_in_b=modules_only_in_b,
        modules_only_in_a=modules_only_in_a,
        modules_changed=modules_changed,
        new_jurisdictions=new_jurisdictions,
        personal_data_delta=personal_data_delta,
        cookies_added=cookies_added,
    )

    return ReportDiff(
        label_a=label_a, label_b=label_b,
        manifest_a=doc_a.manifest, manifest_b=doc_b.manifest,
        capture_status_a=doc_a.capture_status,
        capture_status_b=doc_b.capture_status,
        modules_only_in_a=modules_only_in_a,
        modules_only_in_b=modules_only_in_b,
        modules_changed=modules_changed,
        hosts_only_in_a=hosts_only_in_a,
        hosts_only_in_b=hosts_only_in_b,
        findings_only_in_a=findings_only_in_a,
        findings_only_in_b=findings_only_in_b,
        new_jurisdictions=new_jurisdictions,
        personal_data_delta=personal_data_delta,
        cookies_added=cookies_added,
        cookies_removed=cookies_removed,
        storage_added=storage_added,
        storage_removed=storage_removed,
        bundle_mismatch=bundle_mismatch,
        headline=headline,
    )


# --- per-section diff helpers ---------------------------------------------


def _diff_modules(
    a_modules: list[ModuleSection],
    b_modules: list[ModuleSection],
) -> tuple[list[ModuleSection], list[ModuleSection], list[ModuleChange]]:
    """Split tracker modules into A-only, B-only, and changed-in-both."""
    a_by_id = {m.module_id: m for m in a_modules}
    b_by_id = {m.module_id: m for m in b_modules}

    only_a = [a_by_id[mid] for mid in sorted(set(a_by_id) - set(b_by_id))]
    only_b = [b_by_id[mid] for mid in sorted(set(b_by_id) - set(a_by_id))]

    changed: list[ModuleChange] = []
    for mid in sorted(set(a_by_id) & set(b_by_id)):
        a = a_by_id[mid]
        b = b_by_id[mid]
        a_fields = {hf.key for hf in a.harvested_fields}
        b_fields = {hf.key for hf in b.harvested_fields}
        fields_added = sorted(b_fields - a_fields)
        fields_removed = sorted(a_fields - b_fields)
        hit_count_a = a.total_hits
        hit_count_b = b.total_hits
        # Only include modules where something meaningful changed —
        # identical inputs shouldn't clutter the diff.
        if fields_added or fields_removed or hit_count_a != hit_count_b:
            changed.append(ModuleChange(
                module_id=mid,
                module_name=b.module_name,
                vendor=b.vendor_meta.vendor or "",
                fields_added=fields_added,
                fields_removed=fields_removed,
                hit_count_a=hit_count_a,
                hit_count_b=hit_count_b,
            ))
    return only_a, only_b, changed


def _diff_hosts(
    a_modules: list[ModuleSection],
    b_modules: list[ModuleSection],
) -> tuple[list[str], list[str]]:
    """Split tracker hosts into A-only and B-only sets."""
    a_hosts = _collect_hosts(a_modules)
    b_hosts = _collect_hosts(b_modules)
    return sorted(a_hosts - b_hosts), sorted(b_hosts - a_hosts)


def _collect_hosts(modules: list[ModuleSection]) -> set[str]:
    hosts: set[str] = set()
    for m in modules:
        for rep in m.representative_hits:
            if rep.host:
                hosts.add(rep.host)
    return hosts


def _diff_findings(
    a_findings: list[Finding],
    b_findings: list[Finding],
) -> tuple[list[Finding], list[Finding]]:
    """Diff executive-summary findings by headline.

    Severity + headline together are the natural identity — two
    findings with the same headline but different severity count as a
    change (handled by appearing in BOTH only-lists with the original
    severities on each side).
    """
    a_keys = {(f.severity, f.headline): f for f in a_findings}
    b_keys = {(f.severity, f.headline): f for f in b_findings}
    only_a = [a_keys[k] for k in a_keys if k not in b_keys]
    only_b = [b_keys[k] for k in b_keys if k not in a_keys]
    return only_a, only_b


def _diff_new_jurisdictions(
    a_jur, b_jur,
) -> list[str]:
    """Jurisdictions that appear in B but not A."""
    a_codes = {j.code for j in a_jur if j.code}
    b_codes = {j.code for j in b_jur if j.code}
    return sorted(b_codes - a_codes)


# --- headline summariser ---------------------------------------------------


def _build_headline(
    *,
    label_b: str,
    modules_only_in_b: list,
    modules_only_in_a: list,
    modules_changed: list,
    new_jurisdictions: list[str],
    personal_data_delta: PersonalDataDelta,
    cookies_added: list[CookieEntry],
) -> str:
    """Build a one-line natural-language summary of the delta.

    Severity-aware: leads with new vendors, then names the
    visitor-side impact (new distinct personal-data fields, new
    cookies) so the auditor sees the actual exposure change, not just
    the vendor count. Wording leads with the B-direction because the
    canonical workflow is consent-reject (A) → consent-accept (B):
    the operator wants to know what the accept path unlocks.
    """
    added = len(modules_only_in_b)
    removed = len(modules_only_in_a)
    changed = len(modules_changed)
    new_juris = len(new_jurisdictions)
    new_fields = len(personal_data_delta.only_in_b)
    new_cookies = len(cookies_added)

    if (
        added == 0 and removed == 0 and changed == 0 and new_juris == 0
        and new_fields == 0 and new_cookies == 0
    ):
        return "No change between the two captures."

    parts: list[str] = []
    if added:
        parts.append(
            f"{added} new vendor{'s' if added != 1 else ''}"
        )
    if new_fields:
        parts.append(
            f"{new_fields} new distinct personal-data field"
            f"{'s' if new_fields != 1 else ''}"
        )
    if new_cookies:
        parts.append(
            f"{new_cookies} new tracking cookie"
            f"{'s' if new_cookies != 1 else ''}"
        )
    if changed:
        parts.append(
            f"{changed} vendor{'s' if changed != 1 else ''} with field changes"
        )
    if removed:
        parts.append(
            f"{removed} vendor{'s' if removed != 1 else ''} no longer firing"
        )
    if new_juris:
        codes = ", ".join(new_jurisdictions)
        parts.append(
            f"{new_juris} new jurisdiction{'s' if new_juris != 1 else ''} ({codes})"
        )

    return f"{label_b!r} adds " + "; ".join(parts) + "."


# --- new delta helpers ----------------------------------------------------


def _distinct_personal_fields(analysis: Analysis) -> set[tuple[str, str, str]]:
    """Set of ``(module_name, category, canonical_key)`` for third-party PII.

    Mirrors the per-vendor dedup the verdict's personal-data line uses,
    so the diff and the verdict agree on the field count.
    """
    out: set[tuple[str, str, str]] = set()
    for hit in analysis.hits:
        if not analysis.is_third_party_host(hit.host):
            continue
        for p in hit.params:
            if p.category in (CAT_PII, CAT_IDENTIFIER):
                out.add((hit.module_name, p.category, _canonical_key(p.key)))
    return out


def _diff_personal_data(
    analysis_a: Analysis, analysis_b: Analysis,
) -> PersonalDataDelta:
    """Compute the distinct-field PII/identifier delta between A and B."""
    a = _distinct_personal_fields(analysis_a)
    b = _distinct_personal_fields(analysis_b)
    only_a = sorted(a - b)
    only_b = sorted(b - a)
    return PersonalDataDelta(
        count_a=len(a),
        count_b=len(b),
        only_in_a=[PersonalFieldRef(v, c, k) for v, c, k in only_a],
        only_in_b=[PersonalFieldRef(v, c, k) for v, c, k in only_b],
    )


def _diff_cookies(
    cookies_a: list[CookieEntry], cookies_b: list[CookieEntry],
) -> tuple[list[CookieEntry], list[CookieEntry]]:
    """``(added, removed)`` cookies between A and B, matched by ``(name, host)``.

    Carries the B-side ``CookieEntry`` for added cookies (so renderers
    have the full metadata to display) and the A-side entry for
    removed. Sorted by host then name for deterministic ordering.
    """
    a_keys = {(c.name, c.host): c for c in cookies_a}
    b_keys = {(c.name, c.host): c for c in cookies_b}
    added = [b_keys[k] for k in sorted(set(b_keys) - set(a_keys),
                                       key=lambda x: (x[1], x[0]))]
    removed = [a_keys[k] for k in sorted(set(a_keys) - set(b_keys),
                                         key=lambda x: (x[1], x[0]))]
    return added, removed


def _diff_storage(
    storage_a: list[StorageEntry], storage_b: list[StorageEntry],
) -> tuple[list[StorageEntry], list[StorageEntry]]:
    """``(added, removed)`` storage entries, matched by ``(origin, kind, key)``."""
    a_keys = {(s.origin, s.kind, s.key): s for s in storage_a}
    b_keys = {(s.origin, s.kind, s.key): s for s in storage_b}
    added = [b_keys[k] for k in sorted(set(b_keys) - set(a_keys))]
    removed = [a_keys[k] for k in sorted(set(a_keys) - set(b_keys))]
    return added, removed


def _check_bundle_compat(
    manifest_a: ManifestView, manifest_b: ManifestView,
) -> str | None:
    """Sanity-check that the two bundles are the same site.

    Returns a short warning string when the base domains differ;
    ``None`` when they match. Diffs across different sites produce
    output that is technically valid but semantically meaningless.
    """
    a = (manifest_a.base_domain or "").lower()
    b = (manifest_b.base_domain or "").lower()
    if a and b and a != b:
        return (
            f"Bundles target different sites (A: {a!r}, B: {b!r}). "
            "The diff below is structurally valid but the deltas may "
            "not reflect an apples-to-apples comparison."
        )
    return None


__all__ = [
    "ModuleChange",
    "PersonalDataDelta",
    "PersonalFieldRef",
    "ReportDiff",
    "build_report_diff",
]
