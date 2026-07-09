"""Tests for the diff data model.

Only the data side: ``build_report_diff`` produces correct deltas
between two analyses, and ``render_diff_json`` round-trips the diff
to a dict with the expected top-level keys. The per-format rendered
output (HTML / Markdown / Text) is not tested — that's presentation.
"""

from __future__ import annotations

import json

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent, TYPE_REQUEST
from leak_inspector.modules.base import (
    CAT_IDENTIFIER,
    CAT_PII,
    Hit,
    IMPACT_HIGH,
    ParamInfo,
)
from leak_inspector.report.diff import build_report_diff
from leak_inspector.report.diff_renderers import render_diff_json


def _manifest(target: str = "https://example.be/") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url=target, base_domain="example.be",
        browser={}, profile="p", landing_url=target,
    )


def _hit(*, module_id: str, module_name: str = "M", host: str = "x.example.com",
         params=()) -> Hit:
    param_list = [
        ParamInfo(key=k, value="v", category=c, meaning="",
                  privacy_impact=imp, event_index=1)
        for (k, c, imp) in params
    ]
    return Hit(
        module_id=module_id, module_name=module_name,
        url=f"https://{host}/", host=host, method="GET",
        response_status=200, started_at="t",
        params=param_list, events=[1],
    )


def _analysis(*hits: Hit) -> Analysis:
    a = Analysis(manifest=_manifest())
    a.hits.extend(hits)
    a.untracked_requests.append(RequestEvent(
        event_id=99, timestamp="t", type=TYPE_REQUEST, context_id=None,
        payload={}, method="GET", url="https://example.be/",
        host="example.be", headers={}, request_body=None, initiator=None,
        response_status=200, response_mime=None, response_headers={},
    ))
    return a


def _diff_with_every_delta():
    """One diff covering: tracker-only-in-A, tracker-only-in-B, and a
    tracker in both that gained a new param field on the B side."""
    a = _analysis(
        _hit(module_id="legacy", module_name="Legacy", host="legacy.example.com"),
        _hit(module_id="ga4", module_name="GA4",
             host="www.google-analytics.com",
             params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH)]),
    )
    b = _analysis(
        _hit(module_id="ga4", module_name="GA4",
             host="www.google-analytics.com",
             params=[("cid", CAT_IDENTIFIER, IMPACT_HIGH),
                     ("em",  CAT_PII,        IMPACT_HIGH)]),
        _hit(module_id="facebook_pixel", module_name="Meta Pixel",
             host="www.facebook.com"),
    )
    return build_report_diff(a, b, label_a="reject", label_b="accept")


# --- Diff data shape -------------------------------------------------------


def test_diff_classifies_new_tracker_as_only_in_b() -> None:
    d = _diff_with_every_delta()
    ids = {m.module_id for m in d.modules_only_in_b}
    assert "facebook_pixel" in ids
    assert "legacy" not in ids


def test_diff_classifies_removed_tracker_as_only_in_a() -> None:
    d = _diff_with_every_delta()
    ids = {m.module_id for m in d.modules_only_in_a}
    assert "legacy" in ids
    assert "facebook_pixel" not in ids


def test_diff_records_field_added_on_changed_tracker() -> None:
    d = _diff_with_every_delta()
    ga4_changes = [c for c in d.modules_changed if c.module_id == "ga4"]
    assert len(ga4_changes) == 1
    assert "em" in ga4_changes[0].fields_added


def test_diff_preserves_labels() -> None:
    d = _diff_with_every_delta()
    assert d.label_a == "reject"
    assert d.label_b == "accept"


# --- JSON serialisation contract ------------------------------------------


def test_json_diff_top_level_keys() -> None:
    """Every top-level field of ReportDiff appears in the JSON output.

    Pins the public JSON shape so downstream consumers can rely on it.
    """
    data = json.loads(render_diff_json(_diff_with_every_delta()))
    for key in (
        "label_a", "label_b",
        "manifest_a", "manifest_b",
        "capture_status_a", "capture_status_b",
        "modules_only_in_a", "modules_only_in_b", "modules_changed",
        "hosts_only_in_a", "hosts_only_in_b",
        "findings_only_in_a", "findings_only_in_b",
        "new_jurisdictions", "headline",
    ):
        assert key in data, f"missing top-level key {key!r}"
