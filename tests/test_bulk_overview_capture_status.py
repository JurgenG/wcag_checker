"""Tests for the bulk-tool's capture-status classification.

For each capture the overview classifies the landing-page load as:

* OK             — landing-URL request returned 2xx (or a 3xx that
                   ultimately landed somewhere captured).
* HTTP <NNN> — <Reason>  — landing-URL request returned 4xx/5xx.
* Unreachable    — landing-URL request returned no HTTP status (DNS
                   failure, connection refused, etc.) OR no request
                   to the landing URL exists in the bundle at all.

Failed captures are excluded from the best/worst rankings — they
don't have meaningful 'cleanest' / 'worst' scores — but they remain in
the all-reports table with their status surfaced inline.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Bring bulk-tool/ onto sys.path so the standalone overview module
# imports the same way bulk-tool/run.py does.
_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import overview as overview_module  # noqa: E402

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent, TYPE_REQUEST
from leak_inspector.report.builder import determine_capture_status
from leak_inspector.report.document import CaptureStatus


def _manifest(target: str, landing: str | None = None) -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url=target, base_domain="example.be",
        browser={}, profile="p", landing_url=landing or target,
    )


def _req(url: str, host: str, status: int | None, event_id: int = 1) -> RequestEvent:
    return RequestEvent(
        event_id=event_id, timestamp="t", type=TYPE_REQUEST,
        context_id=None, payload={},
        method="GET", url=url, host=host, headers={},
        request_body=None, initiator=None,
        response_status=status, response_mime=None, response_headers={},
    )


def _analysis_with_landing_request(
    *, target: str, landing: str | None = None, landing_status: int | None,
) -> Analysis:
    """Build an Analysis with a single untracked request to the landing URL."""
    m = _manifest(target=target, landing=landing)
    a = Analysis(manifest=m)
    final_url = landing or target
    a.untracked_requests.append(
        _req(final_url, host=final_url.split("/")[2], status=landing_status)
    )
    return a


# --- _determine_capture_status ---------------------------------------------


def test_status_ok_200() -> None:
    a = _analysis_with_landing_request(
        target="https://example.be/", landing_status=200,
    )
    status = determine_capture_status(a)
    assert status.http_status == 200
    assert status.is_failure is False
    assert "ok" in status.reason.lower()


def test_status_http_404_marked_as_failure() -> None:
    a = _analysis_with_landing_request(
        target="https://example.be/", landing_status=404,
    )
    status = determine_capture_status(a)
    assert status.http_status == 404
    assert status.is_failure is True
    assert "not found" in status.reason.lower()


def test_status_http_418_carries_teapot_reason() -> None:
    """The user's example case: HTTP 418 → 'I'm a Teapot'."""
    a = _analysis_with_landing_request(
        target="https://example.be/", landing_status=418,
    )
    status = determine_capture_status(a)
    assert status.http_status == 418
    assert status.is_failure is True
    assert "teapot" in status.reason.lower()


def test_status_http_500_marked_as_failure() -> None:
    a = _analysis_with_landing_request(
        target="https://example.be/", landing_status=500,
    )
    status = determine_capture_status(a)
    assert status.http_status == 500
    assert status.is_failure is True
    assert "internal server error" in status.reason.lower()


def test_status_unreachable_when_landing_request_has_no_response() -> None:
    """The typo case: DNS / connection failure → response_status is None."""
    a = _analysis_with_landing_request(
        target="https://museumpassmuees.be/",
        landing_status=None,
    )
    status = determine_capture_status(a)
    assert status.http_status is None
    assert status.is_failure is True
    assert "unreachable" in status.reason.lower()


def test_status_unreachable_when_no_landing_request_at_all() -> None:
    """No request to the landing URL was ever made → 'Unreachable'."""
    m = _manifest("https://example.be/")
    a = Analysis(manifest=m)  # no events at all
    status = determine_capture_status(a)
    assert status.is_failure is True
    assert "unreachable" in status.reason.lower()


def test_status_follows_redirects_to_final_landing() -> None:
    """When landing_url differs from target_url (redirect chain), we
    classify based on the request matching the LANDING URL, not the
    first redirect."""
    m = _manifest(
        target="https://example.be",
        landing="https://www.example.be/nl",
    )
    a = Analysis(manifest=m)
    # Redirect chain: target 301 → intermediate 302 → final landing 200.
    a.untracked_requests.append(_req("https://example.be/", "example.be", 301, 1))
    a.untracked_requests.append(_req("https://www.example.be/", "www.example.be", 302, 2))
    a.untracked_requests.append(_req("https://www.example.be/nl", "www.example.be", 200, 3))
    status = determine_capture_status(a)
    assert status.http_status == 200
    assert status.is_failure is False


# --- ranking filter --------------------------------------------------------


def test_failed_captures_excluded_from_best_and_worst_rankings(tmp_path) -> None:
    """Failed captures must not appear in the cleanest / worst-3 cards."""
    from overview import _render_overview_html, SiteSummary

    def _site(slug: str, *, score_high: int, failure: bool) -> SiteSummary:
        status_label = "Unreachable" if failure else "OK"
        return SiteSummary(
            slug=slug, target_url=f"https://{slug}/",
            landing_url=f"https://{slug}/",
            report_filename=f"{slug}.report.html",
            high_finding_count=score_high,
            medium_finding_count=0, low_finding_count=0,
            total_high_impact_fields=0, trackers_fired=0,
            third_party_hosts_touched=0, finding_headlines=[],
            capture_status=CaptureStatus(
                http_status=None if failure else 200,
                reason=status_label,
                is_failure=failure,
            ),
        )

    summaries = [
        _site("clean-a.be",  score_high=0, failure=False),
        _site("clean-b.be",  score_high=0, failure=False),
        _site("clean-c.be",  score_high=0, failure=False),
        _site("worst.be",    score_high=99, failure=False),
        _site("broken.be",   score_high=0, failure=True),   # silent in rankings
    ]
    html = _render_overview_html("test", summaries)

    # broken.be appears in the all-reports table but NOT inside any
    # ranking card (best or worst).
    best_block = html[html.find("Top 3 cleanest"):html.find("Worst 3")]
    worst_block = html[html.find("Worst 3"):html.find("Most common findings")]
    assert "broken.be" not in best_block
    assert "broken.be" not in worst_block
    # Still appears in the all-reports list.
    full_list = html[html.find("All reports"):]
    assert "broken.be" in full_list


def test_full_list_renders_capture_status_for_failed_captures(tmp_path) -> None:
    """The all-reports table shows the failure status inline."""
    from overview import _render_overview_html, SiteSummary

    def _site(slug: str, status: CaptureStatus) -> SiteSummary:
        return SiteSummary(
            slug=slug, target_url=f"https://{slug}/",
            landing_url=f"https://{slug}/",
            report_filename=f"{slug}.report.html",
            high_finding_count=0, medium_finding_count=0, low_finding_count=0,
            total_high_impact_fields=0, trackers_fired=0,
            third_party_hosts_touched=0, finding_headlines=[],
            capture_status=status,
        )

    teapot = CaptureStatus(http_status=418, reason="I'm a Teapot", is_failure=True)
    unreachable = CaptureStatus(http_status=None, reason="Unreachable", is_failure=True)
    summaries = [
        _site("teapot.be", teapot),
        _site("typo.be", unreachable),
    ]
    html = _render_overview_html("test", summaries)
    full_list = html[html.find("All reports"):]
    assert "418" in full_list
    assert "Teapot" in full_list
    assert "Unreachable" in full_list
