"""Tests for the LCP/Icordis consent decision-POST detector.

LCP's server-rendered banner (Icordis CMS, Belgian municipalities)
submits the visitor's choice as a first-party form POST — verified
against the rendered www.beernem.be capture and the historical
multi-site curl markup:

    <form method="post" action="/cookieverklaring?url=%2f">
      <button name="action" value="decline">Alleen essentiële cookies</button>
      <button name="action" value="acceptall">Alles aanvaarden</button>

Constant signals: ``POST``, a localized path containing ``cookie``
(``/cookies``, ``/cookieverklaring``), and the ``action`` body param
with LCP's own values ``acceptall`` / ``decline``. The GET "Beheer
mijn cookies" manage link shares the path but never the method.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis.banner_markup import LCP_ICORDIS_BANNER
from leak_inspector.events import RequestEvent
from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
    Hit,
    all_modules,
)

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


def _request(
    *,
    host: str = "www.beernem.be",
    url: str = "https://www.beernem.be/cookieverklaring?url=%2f",
    method: str = "POST",
    request_body: str | None = "action=decline",
    headers: dict[str, str] | None = None,
    event_id: int = 1,
    timestamp: str = "2026-05-01T12:00:00Z",
    response_status: int | None = 302,
) -> RequestEvent:
    """Build a RequestEvent shaped like the LCP decision POST."""
    if headers is None:
        headers = dict(_FORM_HEADERS) if request_body else {}
    return RequestEvent(
        event_id=event_id,
        timestamp=timestamp,
        type="request",
        context_id=None,
        payload={},
        method=method,
        url=url,
        host=host,
        headers=headers,
        request_body=request_body,
        initiator=None,
        response_status=response_status,
        response_mime=None,
        response_headers={},
    )


@pytest.fixture
def module():
    for m in all_modules():
        if m.module_id == "lcp_icordis_consent":
            return m
    raise AssertionError("lcp_icordis_consent module not registered")


# --- class identity ---------------------------------------------------------


def test_module_name_matches_markup_detector_name(module) -> None:
    """Both detection paths (markup + decision POST) must feed the same
    name into ``consent.cmp_names`` so set-union dedup collapses them."""
    assert module.module_name == LCP_ICORDIS_BANNER


def test_vendor_is_belgian(module) -> None:
    assert module.vendor == "LCP"
    assert module.legal_jurisdiction == "BE"


# --- matches() ---------------------------------------------------------------


@pytest.mark.parametrize("url,body", [
    # beernem's localized path (verified rendered markup)
    ("https://www.beernem.be/cookieverklaring?url=%2f", "action=decline"),
    ("https://www.beernem.be/cookieverklaring?url=%2f", "action=acceptall"),
    # the canonical /cookies path (historical multi-site curl markup)
    ("https://www.boutersem.be/cookies?url=%2f", "action=acceptall"),
])
def test_matches_decision_posts(module, url, body) -> None:
    assert module.matches(_request(url=url, request_body=body))


def test_get_manage_link_does_not_match(module) -> None:
    """The 'Beheer mijn cookies' link GETs the same path — no decision."""
    assert not module.matches(_request(method="GET", request_body=None))


def test_post_without_action_does_not_match(module) -> None:
    assert not module.matches(_request(request_body="q=zwembad"))


def test_other_action_value_does_not_match(module) -> None:
    assert not module.matches(_request(request_body="action=save"))


def test_non_cookie_path_does_not_match(module) -> None:
    """The action values alone are not specific enough — a search or
    login form elsewhere could reuse the name."""
    assert not module.matches(_request(
        url="https://www.beernem.be/contact?url=%2f",
        request_body="action=decline",
    ))


def test_cookie_in_query_only_does_not_match(module) -> None:
    """'cookie' must be in the path, not the querystring."""
    assert not module.matches(_request(
        url="https://www.beernem.be/zoek?q=cookie",
        request_body="action=decline",
    ))


# --- parse() -----------------------------------------------------------------


def test_parse_builds_hit(module) -> None:
    event = _request(request_body="action=acceptall")
    hit = module.parse(event)
    assert isinstance(hit, Hit)
    assert hit.module_id == "lcp_icordis_consent"
    assert hit.host == "www.beernem.be"
    assert hit.method == "POST"
    assert hit.started_at == "2026-05-01T12:00:00Z"
    assert hit.events == [1]


def _classification(module, key: str, body: str) -> tuple[str, str]:
    hit = module.parse(_request(
        url=f"https://www.beernem.be/cookieverklaring?url=%2f&{key}=x"
        if key not in ("action", "url") else
        "https://www.beernem.be/cookieverklaring?url=%2f",
        request_body=body,
    ))
    p = next(p for p in hit.params if p.key == key)
    return p.category, p.privacy_impact


def test_action_param_is_consent(module) -> None:
    category, impact = _classification(module, "action", "action=decline")
    assert category == CAT_CONSENT
    assert impact == IMPACT_LOW


def test_url_param_is_technical(module) -> None:
    """``url`` is the path to return to after the POST — not tracking."""
    category, _ = _classification(module, "url", "action=decline")
    assert category == CAT_TECHNICAL


def test_unknown_param_is_other(module) -> None:
    category, _ = _classification(module, "extra", "action=decline")
    assert category == CAT_OTHER


def test_antiforgery_token_is_technical(module) -> None:
    """ASP.NET Core antiforgery token, observed in the real
    vilvoorde-max decision POST — random CSRF protection, not tracking."""
    hit = module.parse(_request(
        request_body="action=acceptall&__RequestVerificationToken=OLnc-x",
    ))
    p = next(p for p in hit.params if p.key == "__RequestVerificationToken")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW