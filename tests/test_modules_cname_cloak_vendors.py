"""Tests for the CNAME-cloaking vendor detector family.

These vendors are known primarily through first-party-looking
subdomains that CNAME to their canonical collection domains (the
NextDNS cname-cloaking blocklist documents the mappings). The
modules' job is to make the generic CNAME-cloak detector able to
attribute a chain's canonical tail — and to claim the rare direct
hit on those domains.

One combined file: the modules are data-only variations on
``_cname_cloak_base.CnameCloakVendorModule``.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent
from leak_inspector.modules.base import CAT_OTHER, all_modules


#: (module_id, canonical domain, legal_jurisdiction).
#: Domains come from the NextDNS cname-cloaking blocklist plus the
#: vendors' own documented collection domains.
VENDORS: list[tuple[str, str, str]] = [
    ("piano_analytics", "at-o.net", "NL"),
    ("piano_analytics", "xiti.com", "NL"),
    ("eulerian", "eulerian.net", "FR"),
    ("commanders_act", "tagcommander.com", "FR"),
    ("commanders_act", "commander1.com", "FR"),
    ("keyade", "keyade.com", "FR"),
    ("keyade", "madmetrics.com", "FR"),
    ("wizaly", "wizaly.com", "FR"),
    ("act_on", "actonservice.com", "US"),
    ("act_on", "actonsoftware.com", "US"),
    ("oracle_eloqua", "eloqua.com", "US"),
    ("oracle_eloqua", "en25.com", "US"),
    ("webtrekk_mapp", "webtrekk.net", "US"),
    ("webtrekk_mapp", "wt-eu02.net", "US"),
]

_MODULE_IDS = sorted({module_id for module_id, _, _ in VENDORS})


def _module(module_id: str):
    for module in all_modules():
        if module.module_id == module_id:
            return module
    raise AssertionError(f"module {module_id!r} not registered")


def _request(host: str, path: str = "/collect", query: str = "k=v") -> RequestEvent:
    url = f"https://{host}{path}?{query}"
    return RequestEvent(
        event_id=1, timestamp="2026-06-05T10:00:00Z", type="request",
        context_id=None, payload={}, method="GET", url=url, host=host,
        headers={}, request_body=None, initiator=None,
        response_status=200, response_mime=None, response_headers={},
    )


# --- registration + identity ------------------------------------------------


@pytest.mark.parametrize("module_id", _MODULE_IDS)
def test_module_is_registered(module_id: str) -> None:
    assert _module(module_id) is not None


@pytest.mark.parametrize("module_id,domain,jurisdiction", VENDORS)
def test_module_jurisdiction(module_id: str, domain: str, jurisdiction: str) -> None:
    """Jurisdictions feed the resilience score — pin them."""
    assert _module(module_id).legal_jurisdiction == jurisdiction


@pytest.mark.parametrize("module_id", _MODULE_IDS)
def test_module_has_identity(module_id: str) -> None:
    m = _module(module_id)
    assert m.module_name
    assert m.vendor
    assert m.sovereignty_notes


# --- matches() ---------------------------------------------------------------


@pytest.mark.parametrize("module_id,domain,jurisdiction", VENDORS)
def test_matches_canonical_domain_and_subdomains(
    module_id: str, domain: str, jurisdiction: str
) -> None:
    m = _module(module_id)
    assert m.matches(_request(domain)) is True
    assert m.matches(_request(f"collect.{domain}")) is True


@pytest.mark.parametrize("module_id", _MODULE_IDS)
def test_does_not_match_unrelated_hosts(module_id: str) -> None:
    m = _module(module_id)
    assert m.matches(_request("example.com")) is False
    assert m.matches(_request("not-a-tracker.example.be")) is False


def test_lookalike_suffix_not_matched() -> None:
    """``notat-o.net`` must not match ``at-o.net`` — dot-boundary matching."""
    m = _module("piano_analytics")
    assert m.matches(_request("notat-o.net")) is False


# --- parse() -----------------------------------------------------------------


@pytest.mark.parametrize("module_id,domain,jurisdiction", VENDORS[:1])
def test_parse_records_generic_params(
    module_id: str, domain: str, jurisdiction: str
) -> None:
    m = _module(module_id)
    hit = m.parse(_request(domain, query="idclient=abc123"))
    assert hit.module_id == module_id
    assert hit.host == domain
    assert any(p.key == "idclient" for p in hit.params)
    assert all(p.category == CAT_OTHER for p in hit.params)


# --- end-to-end: CNAME-cloak attribution ------------------------------------


def _manifest(base: str = "example.be") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-06-05T00:00:00Z",
        ended_at="2026-06-05T00:01:00Z",
        target_url=f"https://{base}/", base_domain=base,
        browser={}, profile="p", landing_url=f"https://{base}/",
    )


def test_cloaked_subdomain_attributed_via_cname_chain() -> None:
    """A first-party alias CNAMEing to ``at-o.net`` attributes to Piano.

    This is the whole point of the family: the on-the-wire host is
    first-party-looking, the chain's canonical tail names the vendor.
    """
    event = _request("stats.example.be", path="/hit.xiti", query="s=123")
    analysis = analyze_events(
        _manifest(), [event],
        cname_chains={"stats.example.be": ["stats.example.be", "logs.at-o.net"]},
    )
    piano_hits = [h for h in analysis.hits if h.module_id == "piano_analytics"]
    assert piano_hits, "cloaked Piano/AT Internet hit not attributed"
    hit = piano_hits[0]
    assert any(p.key.startswith("(cname-cloak)") for p in hit.params)
