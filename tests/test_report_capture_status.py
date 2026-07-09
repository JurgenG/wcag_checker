"""Tests for ``CaptureStatus`` derivation in ``build_report_document``.

The classifier inspects the landing-page response and produces one
of three outcomes: healthy (2xx), HTTP error (4xx/5xx with reason
phrase), or unreachable (no response). Tests pin the data shape; the
per-format banner rendering is a presentation choice and not pinned.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent, TYPE_REQUEST
from leak_inspector.report import build_report_document


def _manifest(target: str = "https://example.be/") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url=target, base_domain="example.be",
        browser={}, profile="p", landing_url=target,
    )


def _analysis_with_status(status: int | None, target: str = "https://example.be/") -> Analysis:
    a = Analysis(manifest=_manifest(target=target))
    a.untracked_requests.append(RequestEvent(
        event_id=1, timestamp="t", type=TYPE_REQUEST, context_id=None,
        payload={}, method="GET", url=target, host="example.be",
        headers={}, request_body=None, initiator=None,
        response_status=status, response_mime=None, response_headers={},
    ))
    return a


def test_healthy_2xx_is_not_a_failure() -> None:
    status = build_report_document(_analysis_with_status(200)).capture_status
    assert status is not None
    assert status.http_status == 200
    assert status.is_failure is False


def test_http_error_4xx_is_a_failure_with_reason_phrase() -> None:
    status = build_report_document(_analysis_with_status(404)).capture_status
    assert status.is_failure is True
    assert status.http_status == 404
    assert "not found" in status.reason.lower()


def test_unreachable_when_response_status_is_none() -> None:
    """No HTTP response at all (DNS failure, refused connection, etc.)."""
    status = build_report_document(_analysis_with_status(None)).capture_status
    assert status.is_failure is True
    assert status.http_status is None
    assert "unreachable" in status.reason.lower()


def _analysis_with_request(
    *, target: str, landing: str, req_url: str,
    status: int | None, dest: str | None = None,
) -> Analysis:
    """Build an analysis with one request whose URL / Sec-Fetch-Dest differ
    from the manifest target / landing URLs."""
    m = Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url=target, base_domain="example.be",
        browser={}, profile="p", landing_url=landing,
    )
    a = Analysis(manifest=m)
    headers = {"Sec-Fetch-Dest": dest} if dest else {}
    a.untracked_requests.append(RequestEvent(
        event_id=1, timestamp="t", type=TYPE_REQUEST, context_id=None,
        payload={}, method="GET", url=req_url, host="example.be",
        headers=headers, request_body=None, initiator=None,
        response_status=status, response_mime=None, response_headers={},
    ))
    return a


def test_bare_domain_target_matches_trailing_slash_document() -> None:
    """The oosterzele case: a bare-domain target (no trailing slash) must
    match the document request the browser normalized to ``…/`` — exact
    string comparison missed it and reported a false "Unreachable"."""
    a = _analysis_with_request(
        target="https://www.oosterzele.be",
        landing="https://www.oosterzele.be/home",
        req_url="https://www.oosterzele.be/",
        status=200, dest="document",
    )
    status = build_report_document(a).capture_status
    assert status.is_failure is False
    assert status.http_status == 200


def test_spa_landing_url_without_request_falls_back_to_document() -> None:
    """An SPA's client-routed landing_url (``/home``) is never a network
    request; when neither landing nor target matches a request URL, the
    status falls back to the document the browser actually landed on."""
    a = _analysis_with_request(
        target="https://example.be/start",
        landing="https://example.be/home",
        req_url="https://example.be/",
        status=200, dest="document",
    )
    status = build_report_document(a).capture_status
    assert status.is_failure is False
    assert status.http_status == 200


def test_no_document_request_at_all_is_unreachable() -> None:
    """With no URL match and no document request to fall back on, the
    capture is still correctly classified Unreachable."""
    a = _analysis_with_request(
        target="https://example.be/",
        landing="https://example.be/",
        req_url="https://cdn.other.example/x.js",
        status=200, dest="script",
    )
    status = build_report_document(a).capture_status
    assert status.is_failure is True
    assert "unreachable" in status.reason.lower()
