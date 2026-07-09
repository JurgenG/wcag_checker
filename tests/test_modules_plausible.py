"""Tests for the Plausible Analytics module.

Plausible is self-hostable, so jurisdiction is per-instance. By design
Plausible collects no cookies, no persistent visitor ID, no raw IP —
which makes its parameter set noticeably smaller than Matomo / Snowplow.
"""

from __future__ import annotations

import json

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def pl():
    return module_by_id("plausible")


def _api_event_body(
    *, name: str = "pageview",
    url: str = "https://example.be/page",
    domain: str = "example.be",
    referrer: str = "",
    props: dict | None = None,
) -> str:
    payload: dict = {"name": name, "url": url, "domain": domain, "referrer": referrer}
    if props is not None:
        payload["props"] = props
    return json.dumps(payload)


# --- identity ----------------------------------------------------------------


def test_identity(pl) -> None:
    assert pl.module_id == "plausible"
    assert pl.module_name == "Plausible Analytics"
    # Plausible is self-hostable: jurisdiction is per-instance, not per-module.
    assert pl.legal_jurisdiction == ""


# --- matches() ---------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    ["plausible.io", "eu.plausible.io", "ce.plausible.io"],
)
def test_matches_hosted_family(pl, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/js/script.js")
    assert pl.matches(event) is True


def test_matches_api_event_with_plausible_body(pl) -> None:
    """``/api/event`` POST with the documented JSON schema is the strong signal."""
    event = make_request(
        host="analytics.example.com",
        url="https://analytics.example.com/api/event",
        method="POST",
        request_body=_api_event_body(),
    )
    assert pl.matches(event) is True


def test_matches_loader_on_plausible_subdomain(pl) -> None:
    """Self-hosting convention: ``plausible.<operator-domain>`` serving the loader."""
    event = make_request(
        host="plausible.imio.be",
        url="https://plausible.imio.be/js/script.js",
    )
    assert pl.matches(event) is True


@pytest.mark.parametrize(
    "path",
    [
        "/js/script.outbound-links.js",
        "/js/script.hash.js",
        "/js/script.file-downloads.js",
        "/js/script.tagged-events.js",
        "/js/script.outbound-links.tagged-events.js",
    ],
)
def test_matches_loader_variants_on_plausible_subdomain(pl, path: str) -> None:
    event = make_request(host="plausible.example.be", url=f"https://plausible.example.be{path}")
    assert pl.matches(event) is True


def test_matches_legacy_plausible_js_filename_anywhere(pl) -> None:
    """Old loader filename ``plausible.js`` is distinctive — claim on any host."""
    event = make_request(host="analytics.example.com", url="https://analytics.example.com/js/plausible.js")
    assert pl.matches(event) is True


def test_does_not_match_generic_script_js_on_arbitrary_host(pl) -> None:
    """``/js/script.js`` on a non-Plausible host is too generic to claim."""
    event = make_request(host="cdn.example.net", url="https://cdn.example.net/js/script.js")
    assert pl.matches(event) is False


def test_does_not_match_api_event_with_unrelated_body(pl) -> None:
    """``/api/event`` exists on many backends — only Plausible's body schema claims it."""
    event = make_request(
        host="api.example.com",
        url="https://api.example.com/api/event",
        method="POST",
        request_body=json.dumps({"foo": "bar", "type": "click"}),
    )
    assert pl.matches(event) is False


def test_does_not_match_unrelated(pl) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert pl.matches(event) is False


# --- parse() — body params from /api/event ---------------------------------


def test_parse_name_is_behavioral(pl) -> None:
    event = make_request(
        host="plausible.io",
        url="https://plausible.io/api/event",
        method="POST",
        request_body=_api_event_body(name="pageview"),
    )
    hit = pl.parse(event)
    p = next(p for p in hit.params if p.key == "(body) name")
    assert p.category == CAT_BEHAVIORAL


def test_parse_url_is_content(pl) -> None:
    event = make_request(
        host="plausible.io",
        url="https://plausible.io/api/event",
        method="POST",
        request_body=_api_event_body(url="https://example.be/about"),
    )
    hit = pl.parse(event)
    p = next(p for p in hit.params if p.key == "(body) url")
    assert p.category == CAT_CONTENT
    assert "example.be/about" in p.value


def test_parse_domain_is_technical(pl) -> None:
    """``domain`` is the operator-scoped Plausible site identifier — technical."""
    event = make_request(
        host="plausible.io",
        url="https://plausible.io/api/event",
        method="POST",
        request_body=_api_event_body(domain="acme.example.be"),
    )
    hit = pl.parse(event)
    p = next(p for p in hit.params if p.key == "(body) domain")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_parse_referrer_is_content(pl) -> None:
    event = make_request(
        host="plausible.io",
        url="https://plausible.io/api/event",
        method="POST",
        request_body=_api_event_body(referrer="https://duckduckgo.com/"),
    )
    hit = pl.parse(event)
    p = next(p for p in hit.params if p.key == "(body) referrer")
    assert p.category == CAT_CONTENT


def test_parse_props_field_names(pl) -> None:
    """``props`` is an operator-chosen JSON object — surface field names, not values."""
    event = make_request(
        host="plausible.io",
        url="https://plausible.io/api/event",
        method="POST",
        request_body=_api_event_body(props={"plan": "pro", "role": "admin"}),
    )
    hit = pl.parse(event)
    p = next(p for p in hit.params if p.key == "(body) props")
    assert p.category == CAT_BEHAVIORAL
    # Field names visible; values not surfaced (privacy-preserving).
    assert "plan" in p.value and "role" in p.value
    assert "admin" not in p.value
    assert "pro" not in p.value


def test_parse_loader_request_has_no_body_params(pl) -> None:
    """A GET for the loader script has no body — the hit still parses cleanly."""
    event = make_request(host="plausible.io", url="https://plausible.io/js/script.js")
    hit = pl.parse(event)
    assert hit.module_id == "plausible"
    assert all(not p.key.startswith("(body) ") for p in hit.params)


# --- deployment annotation (hosted vs self-hosted) -------------------------


def test_deployment_hosted_annotation(pl) -> None:
    """Hits on plausible.io carry a Plausible Cloud deployment ParamInfo."""
    event = make_request(host="plausible.io", url="https://plausible.io/js/script.js")
    hit = pl.parse(event)
    p = next(p for p in hit.params if p.key == "(deployment) Plausible Cloud")
    meaning = p.meaning.lower()
    assert "estonia" in meaning or "ee" in meaning
    assert not any(p.key == "(deployment) self-hosted" for p in hit.params)


def test_deployment_self_hosted_annotation(pl) -> None:
    """An /api/event hit on a non-hosted host gets the self-hosted ParamInfo."""
    event = make_request(
        host="plausible.imio.be",
        url="https://plausible.imio.be/api/event",
        method="POST",
        request_body=_api_event_body(domain="commune.example.be"),
    )
    hit = pl.parse(event)
    p = next(p for p in hit.params if p.key == "(deployment) self-hosted")
    assert p.privacy_impact == IMPACT_LOW
    assert "operator" in p.meaning.lower()
    assert not any(p.key == "(deployment) Plausible Cloud" for p in hit.params)


# --- detect() routing -------------------------------------------------------


def test_detect_routes_plausible_io_to_module() -> None:
    from leak_inspector.modules.base import detect
    event = make_request(host="plausible.io", url="https://plausible.io/api/event",
                          method="POST", request_body=_api_event_body())
    found = detect(event)
    assert found is not None and found.module_id == "plausible"
