"""Tests for the consentmanager CMP module."""

from __future__ import annotations

import pytest

from leak_inspector.analysis.consent import _CMP_MODULE_IDS
from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def cm():
    return module_by_id("consentmanager")


def test_identity(cm) -> None:
    assert cm.module_id == "consentmanager"
    assert cm.module_name == "consentmanager"
    assert cm.legal_jurisdiction == "DE"


def test_registered_as_cmp() -> None:
    assert "consentmanager" in _CMP_MODULE_IDS


@pytest.mark.parametrize(
    "host",
    [
        "cdn.consentmanager.net",
        "delivery.consentmanager.net",
        "d.delivery.consentmanager.net",
        "consentmanager.net",
        "consentmanager.de",
    ],
)
def test_matches(cm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/delivery/cmp.php")
    assert cm.matches(event) is True


def test_does_not_match_unrelated(cm) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert cm.matches(event) is False


def test_does_not_match_lookalike(cm) -> None:
    event = make_request(
        host="notconsentmanager.com", url="https://notconsentmanager.com/")
    assert cm.matches(event) is False


@pytest.mark.parametrize(
    ("key", "expected_category"),
    [
        ("id", CAT_TECHNICAL),
        ("h", CAT_CONTENT),
        ("l", CAT_TECHNICAL),
        ("o", CAT_TECHNICAL),
        ("t", CAT_TECHNICAL),
        ("__cmpcc", CAT_CONSENT),
        ("__cmpfcc", CAT_CONSENT),
    ],
)
def test_classify_known_params(cm, key: str, expected_category: str) -> None:
    event = make_request(
        host="delivery.consentmanager.net",
        url=f"https://delivery.consentmanager.net/delivery/cmp.php?{key}=v",
    )
    hit = cm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == expected_category


def test_page_url_is_content_medium(cm) -> None:
    """``h`` carries the visited page URL — the privacy-relevant field."""
    event = make_request(
        host="delivery.consentmanager.net",
        url="https://delivery.consentmanager.net/delivery/cmp.php?h=https%3A%2F%2Fwww.bruxelles.be%2F",
    )
    hit = cm.parse(event)
    p = next(p for p in hit.params if p.key == "h")
    assert p.category == CAT_CONTENT
    assert p.privacy_impact == IMPACT_MEDIUM


def test_unknown_param_falls_through(cm) -> None:
    event = make_request(
        host="cdn.consentmanager.net",
        url="https://cdn.consentmanager.net/delivery/cmp.php?weird=1",
    )
    hit = cm.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "consentmanager" in p.meaning
