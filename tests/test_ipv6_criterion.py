"""Tests for the IPv6-support criterion (small-weight, derived from enrichment).

The enrichment already resolves the primary domain's ``AAAA`` records into
``DNSPosture.aaaa_records``. From that we derive a small-weight scoring
criterion and an executive finding:

* IPv6 reachable (AAAA present) → positive 🟢 ``LOW`` finding, no penalty.
* IPv6 absent (no AAAA, but DNS *was* looked up) → ``no_ipv6`` resilience
  deduction + a ``LOW`` finding with an action.
* No DNS posture (un-enriched) → neither fires.

Data-level only (per house rules): asserts the deduction id and the
finding's severity / kind / action, not any rendering.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.dns_posture.types import DNSPosture, IPInfo
from leak_inspector.modules.base import IMPACT_LOW
from leak_inspector.report.builder import build_report_document
from leak_inspector.report.score_v2 import _signal_deductions


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-06-04T00:00:00Z",
        ended_at="2026-06-04T00:01:00Z",
        target_url="https://belgium.be/", base_domain="belgium.be",
        browser={}, profile="p", landing_url="https://belgium.be/",
    )


def _analysis(posture: DNSPosture | None) -> Analysis:
    return Analysis(
        manifest=_manifest(),
        hits=[],
        untracked_requests=[],
        visited_pages=["https://belgium.be/"],
        dns_posture=posture,
    )


def _posture(*, aaaa: bool) -> DNSPosture:
    records = [IPInfo(address="2a02:1800::1", version=6)] if aaaa else []
    return DNSPosture(
        domain="belgium.be",
        looked_up_at="2026-06-04T00:00:00Z",
        a_records=[IPInfo(address="93.184.216.34", version=4)],
        aaaa_records=records,
    )


# --- scoring criterion -------------------------------------------------------


def test_no_aaaa_records_adds_no_ipv6_deduction() -> None:
    ids = {d.source_id for d in _signal_deductions(_analysis(_posture(aaaa=False)))}
    assert "no_ipv6" in ids


def test_aaaa_records_present_adds_no_deduction() -> None:
    ids = {d.source_id for d in _signal_deductions(_analysis(_posture(aaaa=True)))}
    assert "no_ipv6" not in ids


def test_no_posture_does_not_penalise_ipv6() -> None:
    """Un-enriched bundle: no posture, so the criterion stays silent."""
    ids = {d.source_id for d in _signal_deductions(_analysis(None))}
    assert "no_ipv6" not in ids


# --- executive findings ------------------------------------------------------


def test_ipv6_supported_emits_positive_low_finding() -> None:
    doc = build_report_document(_analysis(_posture(aaaa=True)))
    found = [f for f in doc.executive_summary.findings if f.kind == "ipv6_supported"]
    assert len(found) == 1
    f = found[0]
    assert f.severity == IMPACT_LOW
    assert f.action == ""        # positive: no action
    assert f.source == "dns"
    assert "IPv6" in f.headline
    # The negative finding must not also fire.
    assert not any(f.kind == "ipv6_absent" for f in doc.executive_summary.findings)


def test_ipv6_absent_emits_low_finding_with_action() -> None:
    doc = build_report_document(_analysis(_posture(aaaa=False)))
    found = [f for f in doc.executive_summary.findings if f.kind == "ipv6_absent"]
    assert len(found) == 1
    f = found[0]
    assert f.severity == IMPACT_LOW
    assert f.action          # actionable
    assert f.source == "dns"
    assert "IPv6" in f.headline
    assert not any(f.kind == "ipv6_supported" for f in doc.executive_summary.findings)


def test_no_posture_emits_no_ipv6_finding() -> None:
    doc = build_report_document(_analysis(None))
    assert not any(
        f.kind in ("ipv6_supported", "ipv6_absent")
        for f in doc.executive_summary.findings
    )
