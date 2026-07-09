"""Report-layer tests: visited first-party domains are not tallied as third-party.

Exercises the builder's stats + findings against the page-context model:
the redirect origin and visited top-level pages must not appear in the
unclassified-third-party tally, and should be surfaced as visited
first-party domains in the summary.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent, TYPE_REQUEST
from leak_inspector.report.builder import _build_findings, _build_stats


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://museumpas.be",
        base_domain="museumpassmusees.be", browser={}, profile="p",
        landing_url="https://www.museumpassmusees.be/nl",
    )


def _req(event_id: int, host: str) -> RequestEvent:
    return RequestEvent(
        event_id=event_id, timestamp="t", type=TYPE_REQUEST,
        context_id="ctx-aaaa-bbbb-cccc-dddd-eeee", payload={},
        method="GET", url=f"https://{host}/x", host=host, headers={},
        request_body=None, initiator=None, response_status=200,
        response_mime=None, response_headers={},
    )


def _analysis(untracked_hosts: list[str], visited_pages: list[str]) -> Analysis:
    return Analysis(
        manifest=_manifest(),
        hits=[],
        untracked_requests=[_req(i, h) for i, h in enumerate(untracked_hosts, start=1)],
        visited_pages=visited_pages,
    )


def test_redirect_origin_not_counted_as_third_party() -> None:
    analysis = _analysis(
        untracked_hosts=["museumpas.be", "tracker.unknownvendor.io"],
        visited_pages=["https://museumpas.be/", "https://www.museumpassmusees.be/nl"],
    )
    stats = _build_stats(analysis, {})
    # Only the genuine unknown tracker counts; museumpas.be is the entry domain.
    assert stats.third_party_hosts_unclassified == 1


def test_unclassified_finding_excludes_redirect_origin() -> None:
    analysis = _analysis(
        untracked_hosts=["museumpas.be"],
        visited_pages=["https://museumpas.be/"],
    )
    findings = _build_findings(analysis, {})
    unclassified = [f for f in findings if "unclassified third-party" in f.headline.lower()]
    # museumpas.be is first-party (entry), so no unclassified-third-party finding.
    assert unclassified == []


def test_genuine_third_party_still_flagged() -> None:
    analysis = _analysis(
        untracked_hosts=["tracker.unknownvendor.io"],
        visited_pages=["https://www.museumpassmusees.be/nl"],
    )
    findings = _build_findings(analysis, {})
    unclassified = [f for f in findings if "unclassified third-party" in f.headline.lower()]
    assert len(unclassified) == 1
    assert "tracker.unknownvendor.io" in unclassified[0].detail


def test_visited_first_party_domains_surfaced_in_summary() -> None:
    """Visited first-party domains beyond base_domain are mentioned in the report."""
    analysis = _analysis(
        untracked_hosts=[],
        visited_pages=["https://museumpas.be/", "https://www.museumpassmusees.be/nl"],
    )
    findings = _build_findings(analysis, {})
    visited = [f for f in findings if "first-party domain" in f.headline.lower()]
    assert len(visited) == 1
    assert "museumpas.be" in visited[0].detail
