"""Tests for ``leak_inspector.report.diff`` — capture-to-capture comparison.

The diff builder takes two ``Analysis`` objects (typically the same
site captured twice: e.g. consent rejected vs accepted) and produces
a ``ReportDiff`` data structure that the renderers consume.

Tests are TDD-first: each delta case below is asserted against
synthetic Analyses with known shape so the builder logic is exercised
without depending on real captures.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent, TYPE_REQUEST
from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_IDENTIFIER,
    CAT_PII,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
)
from leak_inspector.report.diff import build_report_diff


# --- helpers ----------------------------------------------------------------


def _manifest(target: str = "https://example.be/") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url=target, base_domain="example.be",
        browser={}, profile="p", landing_url=target,
    )


def _hit(
    *, module_id: str, module_name: str = "Some Module",
    host: str = "x.example.com", url_path: str = "/p",
    params: list[tuple[str, str, str]] | None = None,  # (key, category, impact)
    event_id: int = 1,
) -> Hit:
    """Build a Hit with the named param keys (default category/impact don't matter)."""
    param_list: list[ParamInfo] = []
    for key, cat, imp in (params or []):
        param_list.append(ParamInfo(
            key=key, value="v", category=cat, meaning="", privacy_impact=imp,
            event_index=event_id,
        ))
    return Hit(
        module_id=module_id, module_name=module_name,
        url=f"https://{host}{url_path}", host=host, method="GET",
        response_status=200, started_at="t",
        params=param_list, events=[event_id],
    )


def _analysis_with_hits(*hits: Hit) -> Analysis:
    a = Analysis(manifest=_manifest())
    a.hits.extend(hits)
    # The landing-page request, so determine_capture_status returns OK.
    a.untracked_requests.append(RequestEvent(
        event_id=99, timestamp="t", type=TYPE_REQUEST, context_id=None,
        payload={}, method="GET", url="https://example.be/",
        host="example.be", headers={}, request_body=None, initiator=None,
        response_status=200, response_mime=None, response_headers={},
    ))
    return a


# --- identical analyses → empty deltas --------------------------------------


def test_identical_analyses_produce_empty_module_deltas() -> None:
    a = _analysis_with_hits(
        _hit(module_id="ga4", module_name="GA4", host="www.google-analytics.com"),
    )
    b = _analysis_with_hits(
        _hit(module_id="ga4", module_name="GA4", host="www.google-analytics.com"),
    )
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    assert diff.modules_only_in_a == []
    assert diff.modules_only_in_b == []
    # The single module is in both — appears in modules_changed only if
    # there's something to highlight; identical inputs yield no entries.
    assert diff.modules_changed == []
    assert diff.headline.lower().startswith("no change") or \
           "no change" in diff.headline.lower()


def test_identical_analyses_produce_empty_host_deltas() -> None:
    a = _analysis_with_hits(_hit(module_id="x", host="t.example.com"))
    b = _analysis_with_hits(_hit(module_id="x", host="t.example.com"))
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    assert diff.hosts_only_in_a == []
    assert diff.hosts_only_in_b == []


# --- modules only in B (the consent-up case) --------------------------------


def test_tracker_only_in_b_appears_in_modules_only_in_b() -> None:
    a = _analysis_with_hits()  # no trackers — consent declined
    b = _analysis_with_hits(
        _hit(module_id="ga4", module_name="GA4", host="www.google-analytics.com"),
        _hit(module_id="facebook_pixel", module_name="Meta Pixel",
             host="www.facebook.com"),
    )
    diff = build_report_diff(a, b, label_a="reject", label_b="accept")
    ids_b = {m.module_id for m in diff.modules_only_in_b}
    assert ids_b == {"ga4", "facebook_pixel"}
    assert diff.modules_only_in_a == []


def test_tracker_only_in_a_appears_in_modules_only_in_a() -> None:
    a = _analysis_with_hits(_hit(module_id="hotjar", module_name="Hotjar"))
    b = _analysis_with_hits()
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    ids_a = {m.module_id for m in diff.modules_only_in_a}
    assert ids_a == {"hotjar"}


# --- field-set deltas inside a module common to both ------------------------


def test_module_in_both_with_new_field_in_b_records_fields_added() -> None:
    a = _analysis_with_hits(_hit(
        module_id="ga4", host="www.google-analytics.com",
        params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH)],
    ))
    b = _analysis_with_hits(_hit(
        module_id="ga4", host="www.google-analytics.com",
        params=[
            ("cid", CAT_IDENTIFIER, IMPACT_HIGH),
            ("em",  CAT_PII,        IMPACT_HIGH),  # new in B
        ],
    ))
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    assert any(m.module_id == "ga4" and "em" in m.fields_added
               for m in diff.modules_changed)


def test_module_in_both_with_field_dropped_in_b_records_fields_removed() -> None:
    a = _analysis_with_hits(_hit(
        module_id="ga4",
        params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH),
                ("dl",  "content",       IMPACT_MEDIUM)],
    ))
    b = _analysis_with_hits(_hit(
        module_id="ga4",
        params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH)],
    ))
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    assert any(m.module_id == "ga4" and "dl" in m.fields_removed
               for m in diff.modules_changed)


def test_module_in_both_with_no_field_changes_not_in_modules_changed() -> None:
    """A module that fires identically in both shouldn't clutter the diff."""
    a = _analysis_with_hits(_hit(module_id="ga4",
                                 params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH)]))
    b = _analysis_with_hits(_hit(module_id="ga4",
                                 params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH)]))
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    assert all(m.module_id != "ga4" for m in diff.modules_changed)


def test_hit_counts_carried_on_modules_changed() -> None:
    """Two hits in A, five in B — that's a meaningful delta even if the
    field set is identical."""
    a = _analysis_with_hits(
        _hit(module_id="ga4", params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH)], event_id=1),
        _hit(module_id="ga4", params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH)], event_id=2),
    )
    b = _analysis_with_hits(
        *(_hit(module_id="ga4", params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH)], event_id=i)
          for i in range(10, 15)),
    )
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    changes = [m for m in diff.modules_changed if m.module_id == "ga4"]
    assert changes, "ga4 should appear in modules_changed when hit counts differ"
    assert changes[0].hit_count_a == 2
    assert changes[0].hit_count_b == 5


# --- third-party host deltas ------------------------------------------------


def test_host_only_in_b_listed() -> None:
    a = _analysis_with_hits(_hit(module_id="m1", host="a.example.com"))
    b = _analysis_with_hits(
        _hit(module_id="m1", host="a.example.com"),
        _hit(module_id="m2", host="b.example.com"),
    )
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    assert "b.example.com" in diff.hosts_only_in_b
    assert "a.example.com" not in diff.hosts_only_in_b


# --- jurisdiction deltas ----------------------------------------------------


def test_new_jurisdiction_appears_in_new_jurisdictions() -> None:
    """When B contacts a vendor in a jurisdiction A never did, surface it."""
    # Use real registered modules with known jurisdictions to avoid mocking the registry.
    # ga4 → US, matomo → "" (empty, per-instance now). Pick modules with
    # distinct jurisdictions that ship with the project.
    # GA4 (US) only in B → US should appear in new_jurisdictions.
    a = _analysis_with_hits()
    b = _analysis_with_hits(_hit(module_id="ga4", host="www.google-analytics.com"))
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    assert "US" in diff.new_jurisdictions


# --- capture-status pass-through --------------------------------------------


def test_capture_status_carried_on_diff() -> None:
    """Both bundles' capture status flows through the diff."""
    a = _analysis_with_hits()
    b = _analysis_with_hits()
    diff = build_report_diff(a, b, label_a="A", label_b="B")
    assert diff.capture_status_a is not None
    assert diff.capture_status_b is not None
    assert diff.capture_status_a.is_failure is False
    assert diff.capture_status_b.is_failure is False


def test_capture_status_failure_does_not_crash_builder() -> None:
    """A failed capture on either side must not break the diff."""
    a = Analysis(manifest=_manifest())  # no events at all → Unreachable
    b = _analysis_with_hits(_hit(module_id="ga4", host="x.example.com"))
    diff = build_report_diff(a, b, label_a="reject", label_b="accept")
    assert diff.capture_status_a is not None
    assert diff.capture_status_a.is_failure is True
    # Still computes the rest of the diff.
    assert diff.modules_only_in_b


# --- labels carried through -------------------------------------------------


def test_labels_carried_through_to_diff() -> None:
    a = _analysis_with_hits()
    b = _analysis_with_hits()
    diff = build_report_diff(a, b, label_a="consent-reject", label_b="consent-accept")
    assert diff.label_a == "consent-reject"
    assert diff.label_b == "consent-accept"


# --- headline ---------------------------------------------------------------


def test_headline_summarises_delta_when_b_adds_trackers() -> None:
    a = _analysis_with_hits()
    b = _analysis_with_hits(
        _hit(module_id="ga4", host="www.google-analytics.com"),
        _hit(module_id="facebook_pixel", host="www.facebook.com"),
    )
    diff = build_report_diff(a, b, label_a="reject", label_b="accept")
    # The headline mentions the count and the direction.
    assert "2" in diff.headline
    assert "accept" in diff.headline.lower() or "b" in diff.headline.lower()
