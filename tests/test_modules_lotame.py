"""Tests for the Lotame DMP module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def lt():
    return module_by_id("lotame")


def test_identity(lt) -> None:
    assert lt.module_id == "lotame"
    assert lt.module_name == "Lotame"


@pytest.mark.parametrize("host", ["crwdcntrl.net", "bcp.crwdcntrl.net"])
def test_matches(lt, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert lt.matches(event) is True


def test_path_extracts_segments(lt) -> None:
    """Lotame encodes params as ``/map/key=value/key=value/...`` segments."""
    event = make_request(
        host="bcp.crwdcntrl.net",
        url="https://bcp.crwdcntrl.net/map/c=12345/tp=ADBE/tpid=USER123",
    )
    hit = lt.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert "(path) c" in by_key
    assert by_key["(path) c"].value == "12345"
    assert by_key["(path) c"].category == CAT_TECHNICAL
    assert by_key["(path) c"].privacy_impact == IMPACT_LOW
    assert "(path) tp" in by_key
    assert by_key["(path) tp"].value == "ADBE"
    assert by_key["(path) tp"].category == CAT_TECHNICAL
    assert by_key["(path) tp"].privacy_impact == IMPACT_LOW
    assert "(path) tpid" in by_key
    assert by_key["(path) tpid"].value == "USER123"
    assert by_key["(path) tpid"].privacy_impact == IMPACT_HIGH


def test_path_consent_segments(lt) -> None:
    event = make_request(
        host="bcp.crwdcntrl.net",
        url="https://bcp.crwdcntrl.net/map/gdpr=1/gdpr_consent=ABCD",
    )
    hit = lt.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(path) gdpr"].category == CAT_CONSENT
    assert by_key["(path) gdpr_consent"].category == CAT_CONSENT


def test_non_map_path_yields_no_path_params(lt) -> None:
    event = make_request(host="bcp.crwdcntrl.net", url="https://bcp.crwdcntrl.net/other")
    hit = lt.parse(event)
    assert not any(p.key.startswith("(path)") for p in hit.params)


def test_unknown_path_segment_falls_through(lt) -> None:
    event = make_request(
        host="bcp.crwdcntrl.net",
        url="https://bcp.crwdcntrl.net/map/weird=x",
    )
    hit = lt.parse(event)
    p = next(p for p in hit.params if p.key == "(path) weird")
    assert p.category == CAT_OTHER
