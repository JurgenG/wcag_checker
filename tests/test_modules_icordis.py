"""Tests for the Icordis / LCP (Belgian municipal CMS) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ic():
    return module_by_id("icordis")


def test_identity(ic) -> None:
    assert ic.module_id == "icordis"
    # Belgian (EU) vendor: classified so the host leaves "unclassified" and
    # takes the small privacy module-count malus, but — being EU — it draws
    # no resilience / sovereignty penalty (decentralisation, not US big tech).
    assert ic.legal_jurisdiction == "BE"


@pytest.mark.parametrize(
    "host",
    [
        "icordis.be",
        "fonts.icordis.be",
        "icons.icordis.be",
        "static.icordis.be",
        "cdn.icordis.be",
        "chatbotproxy.icordis.be",
    ],
)
def test_matches(ic, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert ic.matches(event) is True


def test_does_not_match_lookalike(ic) -> None:
    event = make_request(host="noticordis.be", url="https://noticordis.be/")
    assert ic.matches(event) is False


def test_does_not_match_unrelated(ic) -> None:
    event = make_request(host="aalst.be", url="https://aalst.be/")
    assert ic.matches(event) is False


def test_params_are_low_impact(ic) -> None:
    event = make_request(
        host="fonts.icordis.be", url="https://fonts.icordis.be/x.woff2?v=3")
    hit = ic.parse(event)
    p = next(p for p in hit.params if p.key == "v")
    assert p.category == CAT_OTHER
