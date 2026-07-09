"""Tests for surfacing forwarded first-party tracker cookies (Phase 4 polish).

The cookie overview stays honest — a forwarded cookie is still rendered
``[1P]`` — but the document carries the ``(name, host)`` keys of cookies
whose vendor forwards/cloaks in this capture, so renderers can attach a
"(via first-party proxy)" note. Forwarded-ness is computed from the hits
(via the scoring helper), never stored on the :class:`CookieEntry`.

Data-level only (per house rules): assert the ``ReportDocument`` field,
not rendered strings.
"""

from __future__ import annotations

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.modules.base import (
    CAT_HTTP_TRAFFIC, IMPACT_MEDIUM, Hit, ParamInfo,
)
from leak_inspector.report.builder import build_report_document
from leak_inspector.report.document import CookieEntry


# --- helpers ---------------------------------------------------------------


def _manifest(base: str = "example.be") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-06-05T00:00:00Z",
        ended_at="2026-06-05T00:01:00Z",
        target_url=f"https://{base}/", base_domain=base,
        browser={}, profile="p", landing_url=f"https://{base}/",
    )


def _hit(module_id: str, host: str, *params: ParamInfo) -> Hit:
    return Hit(
        module_id=module_id, module_name=module_id,
        url=f"https://{host}/", host=host, method="GET",
        response_status=200, started_at="t",
        params=list(params), events=[1],
    )


def _fp_proxy_hit(module_id: str, host: str) -> Hit:
    return _hit(module_id, host, ParamInfo(
        key="(fp-proxy) host", value="x", category=CAT_HTTP_TRAFFIC,
        meaning="", privacy_impact=IMPACT_MEDIUM, event_index=1,
    ))


def _tracker_cookie(
    *,
    name: str = "_ga",
    module_id: str = "ga4",
    lifetime_days: float | None = 400.0,
) -> CookieEntry:
    return CookieEntry(
        name=name, host="example.be", vendor="Google Analytics 4",
        is_first_party=True, lifetime_days=lifetime_days,
        same_site="lax", secure=True, source="stored",
        tracker_module_id=module_id,
    )


def _analysis(*hits: Hit, cookies: tuple[CookieEntry, ...] = ()) -> Analysis:
    return Analysis(
        manifest=_manifest(),
        hits=list(hits),
        untracked_requests=[],
        visited_pages=["https://example.be/"],
        cookies=list(cookies),
    )


# --- document field --------------------------------------------------------


def test_forwarded_cookie_keys_populated_for_fp_mode() -> None:
    """FP-Mode proxy hit + persistent first-party _ga → key on document."""
    doc = build_report_document(_analysis(
        _fp_proxy_hit("google_first_party_mode", "g.example.be"),
        cookies=(_tracker_cookie(),),
    ))
    assert doc.forwarded_cookie_keys == [("_ga", "example.be")]


def test_no_forwarding_means_no_keys() -> None:
    """Ordinary GA (no forwarding marker): the same _ga is not flagged."""
    doc = build_report_document(_analysis(
        _hit("ga4", "www.google-analytics.com"),
        cookies=(_tracker_cookie(),),
    ))
    assert doc.forwarded_cookie_keys == []


def test_forwarded_session_cookie_not_flagged() -> None:
    """The persistence gate of the scoring helper carries through: a
    forwarded vendor's *session* cookie is not noted."""
    doc = build_report_document(_analysis(
        _fp_proxy_hit("google_first_party_mode", "g.example.be"),
        cookies=(_tracker_cookie(name="_gid", lifetime_days=None),),
    ))
    assert doc.forwarded_cookie_keys == []


def test_keys_deduped_and_sorted() -> None:
    """Several forwarded cookies → unique keys in deterministic order."""
    doc = build_report_document(_analysis(
        _fp_proxy_hit("google_first_party_mode", "g.example.be"),
        cookies=(
            _tracker_cookie(name="_ga_ABC"),
            _tracker_cookie(name="_ga"),
            _tracker_cookie(name="_ga"),
        ),
    ))
    assert doc.forwarded_cookie_keys == [
        ("_ga", "example.be"), ("_ga_ABC", "example.be"),
    ]
