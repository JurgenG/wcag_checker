"""Tests for the security-response-header evaluator.

``evaluate_security_headers`` turns the captured main-document response
headers (``Analysis.security_headers``) into a structured per-header
status list for the report — reusing the *same* presence predicates the
score already keys on, so the rendered "Security headers" section and the
``*_missing`` deductions can never disagree.

``None`` in (no document response observed) → ``None`` out (the report
stays silent); ``{}`` (response seen, no headers) → every header marked
absent.
"""

from __future__ import annotations

from leak_inspector.report.score_v2 import (
    HeaderCheck,
    evaluate_security_headers,
)

_ALL_PRESENT = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


def _by_key(checks):
    return {c.key: c for c in checks}


def test_none_headers_returns_none() -> None:
    """Not probed → silent (distinct from 'probed, none present')."""
    assert evaluate_security_headers(None) is None


def test_empty_dict_marks_every_header_absent() -> None:
    checks = evaluate_security_headers({})
    assert checks is not None
    assert len(checks) == 6
    assert all(not c.ok for c in checks)
    assert all(c.value == "" for c in checks)


def test_all_present_marks_every_header_ok_with_value() -> None:
    checks = _by_key(evaluate_security_headers(_ALL_PRESENT))
    assert all(c.ok for c in checks.values())
    assert checks["content-security-policy"].value == "default-src 'self'"
    assert checks["x-frame-options"].value == "DENY"


def test_reuses_scoring_predicates_for_edge_values() -> None:
    """The evaluator must agree with the score predicates: max-age=0 HSTS,
    unsafe-url referrer, and a non-nosniff XCTO all count as NOT ok."""
    checks = _by_key(evaluate_security_headers({
        "strict-transport-security": "max-age=0",
        "referrer-policy": "unsafe-url",
        "x-content-type-options": "sniff-me",
    }))
    assert checks["strict-transport-security"].ok is False
    assert checks["referrer-policy"].ok is False
    assert checks["x-content-type-options"].ok is False
    # The raw values are still carried for display.
    assert checks["strict-transport-security"].value == "max-age=0"


def test_order_is_stable_and_canonical() -> None:
    keys = [c.key for c in evaluate_security_headers({})]
    assert keys == [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]


def test_headercheck_is_frozen() -> None:
    check = evaluate_security_headers({})[0]
    assert isinstance(check, HeaderCheck)
