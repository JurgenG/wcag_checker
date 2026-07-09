"""Tests for the cookie overview section in every per-site report.

Each captured response's ``Set-Cookie`` header(s) are extracted into
structured ``CookieEntry`` objects with name, host, vendor, 1p/3p flag,
lifetime, and security attributes. The report renders these as a
dedicated overview block separate from the per-tracker drill-downs.

Tests focus on the parsing → builder pipeline; format-specific
rendering is covered in tests/test_report_screenshot* (analogous
pattern) and tests/test_report_capture_status.py.
"""

from __future__ import annotations

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent, TYPE_REQUEST
from leak_inspector.report import build_report_document
from leak_inspector.report.document import CookieEntry


def _manifest(target: str = "https://example.be/") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-05-29T00:00:00Z",
        ended_at="2026-05-29T00:01:00Z",
        target_url=target, base_domain="example.be",
        browser={}, profile="p", landing_url=target,
    )


def _request_with_cookies(
    *, host: str, url: str, set_cookie_value: str,
    event_id: int = 1, response_status: int = 200,
) -> RequestEvent:
    return RequestEvent(
        event_id=event_id, timestamp="2026-05-29T00:00:01Z",
        type=TYPE_REQUEST, context_id=None, payload={},
        method="GET", url=url, host=host, headers={},
        request_body=None, initiator=None,
        response_status=response_status, response_mime="text/html",
        response_headers={"set-cookie": set_cookie_value},
    )


# --- one cookie surfaces with correct attributes ---------------------------


def test_simple_cookie_surfaces_with_name_and_host() -> None:
    """A single Set-Cookie on the landing page lands in document.cookies."""
    events = [_request_with_cookies(
        host="example.be",
        url="https://example.be/",
        set_cookie_value="sessionid=abc123; Max-Age=3600; Path=/; HttpOnly",
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    assert doc.cookies, "expected at least one cookie on the document"
    names = {c.name for c in doc.cookies}
    assert "sessionid" in names


def test_cookie_carries_security_flags() -> None:
    events = [_request_with_cookies(
        host="x.example.com", url="https://x.example.com/",
        set_cookie_value=(
            "ga=GA1.1.123; Max-Age=63072000; Path=/; Domain=.example.com; "
            "Secure; HttpOnly; SameSite=Lax"
        ),
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    cookie = next(c for c in doc.cookies if c.name == "ga")
    assert cookie.secure is True
    assert cookie.http_only is True
    assert cookie.partitioned is False
    assert cookie.same_site.lower() == "lax"
    assert cookie.domain == ".example.com"
    assert cookie.path == "/"


def test_cookie_parses_partitioned_flag() -> None:
    events = [_request_with_cookies(
        host="x.example.com", url="https://x.example.com/",
        set_cookie_value="cid=foo; Max-Age=86400; Secure; Partitioned; SameSite=None",
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    c = next(c for c in doc.cookies if c.name == "cid")
    assert c.partitioned is True


def test_cookie_lifetime_max_age() -> None:
    events = [_request_with_cookies(
        host="x.example.com", url="https://x.example.com/",
        set_cookie_value="a=v; Max-Age=2592000",  # 30 days
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    c = next(c for c in doc.cookies if c.name == "a")
    assert c.max_age_seconds == 2592000
    assert c.lifetime_days is not None
    assert 29.5 < c.lifetime_days < 30.5
    # Human label like "~30d".
    assert "30" in c.lifetime_human


def test_session_cookie_when_no_max_age_or_expires() -> None:
    events = [_request_with_cookies(
        host="x.example.com", url="https://x.example.com/",
        set_cookie_value="sess=v; Path=/",
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    c = next(c for c in doc.cookies if c.name == "sess")
    assert c.max_age_seconds is None
    assert c.lifetime_days is None
    assert c.lifetime_human == "session"


# --- first-party vs third-party classification -----------------------------


def test_cookie_set_by_first_party_marked_first_party() -> None:
    events = [_request_with_cookies(
        host="example.be",  # matches manifest's base_domain
        url="https://example.be/",
        set_cookie_value="own=1; Max-Age=3600",
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    c = next(c for c in doc.cookies if c.name == "own")
    assert c.is_first_party is True


def test_cookie_set_by_third_party_marked_third_party() -> None:
    events = [_request_with_cookies(
        host="tracker.example.com",
        url="https://tracker.example.com/pixel",
        set_cookie_value="tid=xyz; Max-Age=2592000; SameSite=None; Secure",
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    c = next(c for c in doc.cookies if c.name == "tid")
    assert c.is_first_party is False


# --- privacy impact classification -----------------------------------------


def test_persistent_third_party_samesite_none_is_high_impact() -> None:
    events = [_request_with_cookies(
        host="tracker.example.com",
        url="https://tracker.example.com/",
        set_cookie_value="t=v; Max-Age=31536000; SameSite=None; Secure",
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    c = next(c for c in doc.cookies if c.name == "t")
    assert c.privacy_impact == "high"


def test_partitioned_cookie_is_low_impact() -> None:
    """Partitioned (CHIPS) cookies can't follow users across sites — LOW."""
    events = [_request_with_cookies(
        host="tracker.example.com",
        url="https://tracker.example.com/",
        set_cookie_value="t=v; Max-Age=31536000; SameSite=None; Secure; Partitioned",
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    c = next(c for c in doc.cookies if c.name == "t")
    assert c.privacy_impact == "low"


# --- multi-cookie + multi-host -------------------------------------------


def test_multiple_cookies_on_same_response_all_surfaced() -> None:
    """Bundle stores multiple Set-Cookie headers joined by newlines."""
    events = [_request_with_cookies(
        host="x.example.com", url="https://x.example.com/",
        set_cookie_value=(
            "a=1; Max-Age=60\n"
            "b=2; Max-Age=120; HttpOnly\n"
            "c=3; Max-Age=180; Secure"
        ),
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    names = sorted(c.name for c in doc.cookies)
    assert names == ["a", "b", "c"]


def test_same_cookie_name_on_different_hosts_treated_as_distinct() -> None:
    events = [
        _request_with_cookies(
            host="example.be", url="https://example.be/",
            set_cookie_value="session=v; Max-Age=3600", event_id=1,
        ),
        _request_with_cookies(
            host="tracker.example.com", url="https://tracker.example.com/",
            set_cookie_value="session=w; Max-Age=3600", event_id=2,
        ),
    ]
    doc = build_report_document(analyze_events(_manifest(), events))
    by_host = {c.host: c for c in doc.cookies if c.name == "session"}
    assert "example.be" in by_host
    assert "tracker.example.com" in by_host
    assert by_host["example.be"].is_first_party is True
    assert by_host["tracker.example.com"].is_first_party is False


def test_no_cookies_when_no_set_cookie_headers() -> None:
    """A capture with no Set-Cookie anywhere → empty cookies list."""
    events = [RequestEvent(
        event_id=1, timestamp="t", type=TYPE_REQUEST, context_id=None,
        payload={}, method="GET", url="https://example.be/",
        host="example.be", headers={}, request_body=None, initiator=None,
        response_status=200, response_mime=None, response_headers={},
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    assert doc.cookies == []


# --- ReportDocument carries the list ---------------------------------------


def test_cookies_is_a_top_level_field_on_report_document() -> None:
    """The cookie list is part of the document contract — reporters can
    rely on it being present (possibly empty)."""
    events = [_request_with_cookies(
        host="example.be", url="https://example.be/",
        set_cookie_value="a=v; Max-Age=60",
    )]
    doc = build_report_document(analyze_events(_manifest(), events))
    assert hasattr(doc, "cookies")
    assert isinstance(doc.cookies, list)
    assert all(isinstance(c, CookieEntry) for c in doc.cookies)
