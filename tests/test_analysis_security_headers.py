"""Main-document security-header extraction (Phase 1a).

``analyze_events`` records the response headers of the main document —
the request whose ``url`` equals the manifest's ``landing_url`` — onto
``Analysis.security_headers`` (keys lowercased). This is the certain
correlation: a ``RequestEvent`` carries no resource-type, so matching
the landing URL is the only signal that picks the document response
rather than an arbitrary sub-resource.

The headers are read offline from the captured stream — no network,
no re-fetch — so the CSP / HSTS posture reflects what the visitor's
browser actually received during the session.

Real fixtures pin the behaviour against certain data:

* ``doccle-accept.zip`` — landing response carries both
  ``Content-Security-Policy`` and ``Strict-Transport-Security``.
* ``aalst.zip`` — landing response carries HSTS only (no CSP).

A synthetic no-match case covers the "no document response observed"
path (``security_headers is None``).
"""

from __future__ import annotations

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis import analyze_bundle, analyze_events
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import (
    RequestEvent,
    TYPE_REQUEST,
)

from tests.fixtures.bundles import path as bundle_path


# --- helpers ---------------------------------------------------------------


def _manifest(*, landing: str, base: str = "example.be") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url=f"https://{base}/", base_domain=base, browser={},
        profile="p", landing_url=landing,
    )


def _req(
    event_id: int, url: str, *, response_headers: dict[str, str] | None = None,
) -> RequestEvent:
    return RequestEvent(
        event_id=event_id, timestamp="t", type=TYPE_REQUEST,
        context_id="ctx", payload={},
        method="GET", url=url, host="example.be", headers={},
        request_body=None, initiator=None, response_status=200,
        response_mime=None, response_headers=response_headers or {},
    )


# --- real-bundle extraction (certain data) ---------------------------------


def test_landing_response_with_both_headers() -> None:
    """doccle-accept's landing response carries CSP + HSTS."""
    analysis = analyze_bundle(bundle_path("doccle-accept.zip"))
    sh = analysis.security_headers
    assert sh is not None
    assert "content-security-policy" in sh
    assert "strict-transport-security" in sh


def test_landing_response_hsts_only() -> None:
    """aalst's landing response carries HSTS but no CSP."""
    analysis = analyze_bundle(bundle_path("aalst.zip"))
    sh = analysis.security_headers
    assert sh is not None
    assert "strict-transport-security" in sh
    assert "content-security-policy" not in sh


def test_keys_are_lowercased() -> None:
    """Header keys are normalised to lowercase regardless of capture casing."""
    analysis = analyze_bundle(bundle_path("doccle-accept.zip"))
    sh = analysis.security_headers
    assert sh is not None
    assert all(k == k.lower() for k in sh)


# --- synthetic correlation + no-match path ---------------------------------


def test_extracts_headers_from_matching_landing_request() -> None:
    """The response of the request whose url == landing_url is captured."""
    landing = "https://example.be/home"
    manifest = _manifest(landing=landing)
    events = [
        _req(1, "https://example.be/asset.js",
             response_headers={"Content-Security-Policy": "ignored"}),
        _req(2, landing, response_headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
        }),
    ]
    analysis = analyze_events(manifest, events)
    assert analysis.security_headers == {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
    }


def test_none_when_no_request_matches_landing_url() -> None:
    """No document response observed → security_headers is None (not {})."""
    manifest = _manifest(landing="https://example.be/never-seen")
    events = [
        _req(1, "https://example.be/other",
             response_headers={"Strict-Transport-Security": "max-age=1"}),
    ]
    analysis = analyze_events(manifest, events)
    assert analysis.security_headers is None