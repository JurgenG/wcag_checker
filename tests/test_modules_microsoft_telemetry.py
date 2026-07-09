"""Tests for the Microsoft 1DS / Aria telemetry module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("microsoft_telemetry")


def test_identity(m) -> None:
    assert m.module_id == "microsoft_telemetry"
    assert m.legal_jurisdiction == "US"


def test_matches_onecollector_and_aria(m) -> None:
    for host in ("eu-office.events.data.microsoft.com",
                 "eu-mobile.events.data.microsoft.com",
                 "eu.pipe.aria.microsoft.com"):
        event = make_request(host=host, url=f"https://{host}/OneCollector/1.0/")
        assert m.matches(event) is True


def test_does_not_match_other_hosts(m) -> None:
    for host in ("bookings.cloud.microsoft", "clarity.ms",
                 "dc.services.visualstudio.com", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_query_apikey_is_technical_not_visitor(m) -> None:
    url = ("https://eu.pipe.aria.microsoft.com/Collector/3.0/"
           "?qsp=true&client-id=NO_AUTH&sdk-version=AWT-Web-CJS-1.2.0"
           "&x-apikey=be1d9a81bac24c64a00c2443b1c02d6e-689a8828")
    hit = m.parse(make_request(host="eu.pipe.aria.microsoft.com", url=url))
    apikey = next(p for p in hit.params if p.key == "x-apikey")
    assert apikey.category == CAT_TECHNICAL


def test_body_event_name_is_behavioral(m) -> None:
    body = ('{"name":"Office.Forms.Web.Perf.Endpoint.ResponsePage",'
            '"time":"2026-06-20T01:52:32.618Z","ver":"4.0",'
            '"iKey":"o:4e990506778b4d9cbf05300e98315eed",'
            '"ext":{"sdk":{"seq":1,"ver":"1DS-Web-JS-3.2.15"}}}')
    event = make_request(
        host="eu-mobile.events.data.microsoft.com",
        url="https://eu-mobile.events.data.microsoft.com/OneCollector/1.0/",
        method="POST",
        request_body=body,
    )
    hit = m.parse(event)
    name = next(p for p in hit.params if p.key == "(body) name")
    assert name.category == CAT_BEHAVIORAL
    assert name.value == "Office.Forms.Web.Perf.Endpoint.ResponsePage"
    sdk = next(p for p in hit.params if p.key == "(body) ext.sdk.ver")
    assert sdk.value == "1DS-Web-JS-3.2.15"
