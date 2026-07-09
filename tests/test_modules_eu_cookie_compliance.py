"""Detector for Drupal's EU Cookie Compliance (GDPR Compliance) module.

A self-hosted, first-party consent banner — extremely common on EU
public-sector Drupal sites. Unlike hosted CMPs (Cookiebot/OneTrust) it
has no vendor host: it's recognised by its canonical contrib asset
path, ``/modules/contrib/eu_cookie_compliance/…``. Its decision lives
in the first-party ``cookie-agreed`` cookie.
"""

from __future__ import annotations

import pytest

from leak_inspector.events import RequestEvent
from leak_inspector.modules import all_modules


def _module():
    for m in all_modules():
        if m.module_id == "eu_cookie_compliance":
            return m
    raise AssertionError("eu_cookie_compliance module not registered")


def _request(url: str, host: str = "etterbeek.brussels") -> RequestEvent:
    return RequestEvent(
        event_id=1, timestamp="2026-06-05T22:56:17Z", type="request",
        context_id="ctx", payload={}, method="GET", url=url, host=host,
        headers={}, request_body=None, initiator=None,
        response_status=200, response_mime="application/javascript",
        response_headers={},
    )


_JS = (
    "https://etterbeek.brussels/modules/contrib/eu_cookie_compliance/"
    "js/eu_cookie_compliance.min.js?v=9.5.12-dev"
)


def test_registered() -> None:
    assert _module().module_id == "eu_cookie_compliance"


def test_matches_canonical_contrib_js() -> None:
    assert _module().matches(_request(_JS)) is True


def test_does_not_match_other_first_party_assets() -> None:
    other = _request("https://etterbeek.brussels/themes/custom/site.js")
    assert _module().matches(other) is False


def test_identity_is_first_party_drupal() -> None:
    m = _module()
    assert "EU Cookie Compliance" in m.module_name
    # Self-hosted GPL module — no third-party vendor jurisdiction.
    assert m.legal_jurisdiction in ("", None) or m.module_kind != "tracker"


def test_parse_yields_a_hit_attributed_to_the_module() -> None:
    hit = _module().parse(_request(_JS))
    assert hit.module_id == "eu_cookie_compliance"
    assert hit.host == "etterbeek.brussels"
