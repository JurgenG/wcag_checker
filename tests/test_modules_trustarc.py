"""Tests for the TrustArc / TRUSTe module.

Built from real captured traffic (now committed at
``tests/fixtures/bundles/kbc.zip``); not
speculation. Observed hosts: ``consent.trustarc.com``,
``consent.truste.com``. Observed paths: ``/notice``, ``/asset/notice.js``,
``/analytics``, ``/cm/<domain>/modalconfig``, ``/consent/log``,
``/get?name=...``.
"""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ta():
    return module_by_id("trustarc")


# --- A. identity ------------------------------------------------------------


def test_identity(ta) -> None:
    assert ta.module_id == "trustarc"
    assert ta.module_name == "TrustArc (formerly TRUSTe)"
    assert ta.vendor == "TrustArc Inc. (formerly TRUSTe, Inc.)"
    assert ta.legal_jurisdiction == "US"
    assert ta.data_residency
    assert ta.sovereignty_notes


# --- B. matches() -----------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "trustarc.com",
        "consent.trustarc.com",
        "truste.com",
        "consent.truste.com",
    ],
)
def test_matches_trustarc_and_truste_hosts(ta, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/notice")
    assert ta.matches(event) is True


def test_matches_is_case_insensitive(ta) -> None:
    event = make_request(
        host="CONSENT.TRUSTARC.COM",
        url="https://CONSENT.TRUSTARC.COM/notice",
    )
    assert ta.matches(event) is True


def test_does_not_match_lookalike(ta) -> None:
    """Conservative — ``nottrusted.com`` etc. must NOT match."""
    event = make_request(host="nottrusted.com", url="https://nottrusted.com/")
    assert ta.matches(event) is False


def test_does_not_match_unrelated(ta) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert ta.matches(event) is False


# --- C. parse() — Hit construction -----------------------------------------


def test_parse_returns_hit_metadata(ta) -> None:
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/notice?domain=exp-w1.kbc.be&c=teconsent",
        event_id=42,
        timestamp="2026-05-27T16:55:17Z",
    )
    hit = ta.parse(event)
    assert isinstance(hit, Hit)
    assert hit.module_id == "trustarc"
    assert hit.module_name == "TrustArc (formerly TRUSTe)"
    assert hit.events == [42]
    assert hit.started_at == "2026-05-27T16:55:17Z"


# --- D. classification ------------------------------------------------------


def test_domain_is_content(ta) -> None:
    """``domain`` is the embedding publisher site — content / context, not id."""
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/notice?domain=exp-w1.kbc.be",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "domain")
    assert p.category == CAT_CONTENT
    assert p.privacy_impact == IMPACT_MEDIUM


def test_referer_is_content(ta) -> None:
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/analytics?referer=https://www.kbc.be",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "referer")
    assert p.category == CAT_CONTENT


def test_session_is_identifier(ta) -> None:
    """``session`` is a per-visit visitor pseudonym."""
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/analytics?session=de63eefd744146f889c7006235b60eeb",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "session")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_MEDIUM


def test_type_is_technical(ta) -> None:
    """``type`` on /modalconfig is the per-customer banner template (property-scoped)."""
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/cm/exp-w1.kbc.be/modalconfig?type=exp_w1_kbc_be_v4",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "type")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_action_is_behavioral(ta) -> None:
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/analytics?action=18",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "action")
    assert p.category == CAT_BEHAVIORAL


def test_categories_is_consent(ta) -> None:
    """``categories`` reveals which consent categories the visitor accepted."""
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/analytics?categories=1",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "categories")
    assert p.category == CAT_CONSENT


def test_implied_is_consent(ta) -> None:
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/analytics?implied=0",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "implied")
    assert p.category == CAT_CONSENT


def test_new_visitor_is_behavioral(ta) -> None:
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/analytics?new=1",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "new")
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize(
    "key",
    ["language", "locale", "country", "layout", "text", "pcookie", "gtm", "v", "name", "c"],
)
def test_banner_config_keys_are_technical(ta, key: str) -> None:
    event = make_request(
        host="consent.trustarc.com",
        url=f"https://consent.trustarc.com/notice?{key}=x",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_unknown_param_falls_through(ta) -> None:
    event = make_request(
        host="consent.trustarc.com",
        url="https://consent.trustarc.com/notice?weird=1",
    )
    hit = ta.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "TrustArc" in p.meaning
