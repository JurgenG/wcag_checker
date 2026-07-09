"""Tests for the Microsoft Office configuration (ODC) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("microsoft_office_config")


def test_identity(m) -> None:
    assert m.module_id == "microsoft_office_config"
    assert m.legal_jurisdiction == "US"


def test_matches_odc_host(m) -> None:
    url = ("https://odc.officeapps.live.com/odc/v2.1/federationprovider"
           "?domain=ff9fbf87-2145-4724-a5b5-b1b4ad52151b")
    event = make_request(host="odc.officeapps.live.com", url=url)
    assert m.matches(event) is True


def test_does_not_match_other_hosts(m) -> None:
    for host in ("officeapps.live.com", "bookings.cloud.microsoft",
                 "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_domain_param_is_technical(m) -> None:
    url = ("https://odc.officeapps.live.com/odc/v2.1/federationprovider"
           "?domain=ff9fbf87-2145-4724-a5b5-b1b4ad52151b")
    hit = m.parse(make_request(host="odc.officeapps.live.com", url=url))
    dom = next(p for p in hit.params if p.key == "domain")
    assert dom.category == CAT_TECHNICAL
