"""Tests for the server-sovereignty criterion (physical + jurisdiction).

For each infrastructure component — web host (A/AAAA), mail (MX host IPs),
and DNS (nameserver IPs) — two independent facts are scored against the
EU:

* physical location, from geoip ``IPInfo.country_code`` (−2 resilience),
* legal jurisdiction, from the ASN registration country
  ``IPInfo.asn_country`` (−3 resilience).

Both axes cumulate and the three components score independently. Empty /
unknown codes never fire (no penalty for data we could not determine).
Data-level only: asserts which signal ids fire, not rendering.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.dns_posture.types import (
    DNSPosture, HostRecord, IPInfo, NameserverRecord,
)
from leak_inspector.report.score_v2 import _signal_deductions


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://x.be/", base_domain="x.be",
        browser={}, profile="p", landing_url="https://x.be/",
    )


def _ip(country: str = "", asn_country: str = "") -> IPInfo:
    return IPInfo(address="1.2.3.4", version=4,
                  country_code=country, asn_country=asn_country)


def _posture(*, host=None, mail=None, dns=None) -> DNSPosture:
    return DNSPosture(
        domain="x.be", looked_up_at="t",
        a_records=host or [],
        mx=[HostRecord(name="mx.x.be", ips=mail)] if mail else [],
        nameservers=[NameserverRecord(name="ns.x.be", ips=dns)] if dns else [],
    )


def _ids(posture: DNSPosture | None) -> set[str]:
    analysis = Analysis(manifest=_manifest(), dns_posture=posture)
    return {d.source_id for d in _signal_deductions(analysis)}


# --- host: the two axes fire independently -----------------------------------


def test_host_extra_eu_both_axes_fire() -> None:
    ids = _ids(_posture(host=[_ip(country="US", asn_country="US")]))
    assert "host_physical_extra_eu" in ids
    assert "host_jurisdiction_extra_eu" in ids


def test_host_in_eu_fires_nothing() -> None:
    ids = _ids(_posture(host=[_ip(country="BE", asn_country="BE")]))
    assert "host_physical_extra_eu" not in ids
    assert "host_jurisdiction_extra_eu" not in ids


def test_physical_outside_eu_but_eu_jurisdiction_fires_physical_only() -> None:
    """The Akamai case: IP geolocates to the US, ASN registered in the EU."""
    ids = _ids(_posture(host=[_ip(country="US", asn_country="NL")]))
    assert "host_physical_extra_eu" in ids
    assert "host_jurisdiction_extra_eu" not in ids


def test_eu_physical_but_foreign_jurisdiction_fires_jurisdiction_only() -> None:
    """The Schrems II case: server in the EU, operator under a foreign regime."""
    ids = _ids(_posture(host=[_ip(country="IE", asn_country="US")]))
    assert "host_physical_extra_eu" not in ids
    assert "host_jurisdiction_extra_eu" in ids


# --- per-component independence ----------------------------------------------


def test_mail_and_dns_components_fire_their_own_signals() -> None:
    posture = _posture(
        host=[_ip(country="BE", asn_country="BE")],          # clean
        mail=[_ip(country="US", asn_country="US")],          # both
        dns=[_ip(country="US", asn_country="US")],           # both
    )
    ids = _ids(posture)
    assert "host_physical_extra_eu" not in ids
    assert {"mail_physical_extra_eu", "mail_jurisdiction_extra_eu",
            "dns_physical_extra_eu", "dns_jurisdiction_extra_eu"} <= ids


def test_full_extra_eu_stack_fires_all_six() -> None:
    us = [_ip(country="US", asn_country="US")]
    ids = _ids(_posture(host=us, mail=us, dns=us))
    assert {
        "host_physical_extra_eu", "host_jurisdiction_extra_eu",
        "mail_physical_extra_eu", "mail_jurisdiction_extra_eu",
        "dns_physical_extra_eu", "dns_jurisdiction_extra_eu",
    } <= ids


# --- certainty: unknown / absent never penalises -----------------------------


def test_empty_country_codes_fire_nothing() -> None:
    ids = _ids(_posture(host=[_ip()], mail=[_ip()], dns=[_ip()]))
    assert not any("extra_eu" in s for s in ids)


def test_no_posture_fires_no_sovereignty_signals() -> None:
    ids = _ids(None)
    assert not any("extra_eu" in s for s in ids)


# --- jurisdiction fallback: bundles enriched before asn_country existed -------


def test_jurisdiction_falls_back_to_as_org_suffix() -> None:
    """Old bundles have no asn_country, but Cymru's ', CC' suffix on as_org
    still carries the registration country."""
    ip = IPInfo(address="1.2.3.4", version=4, country_code="US",
                as_org="GOOGLE-CLOUD-PLATFORM - Google LLC, US")
    ids = _ids(_posture(host=[ip]))
    assert "host_jurisdiction_extra_eu" in ids


def test_eu_registered_as_org_suffix_does_not_fire_jurisdiction() -> None:
    ip = IPInfo(address="1.2.3.4", version=4, country_code="US",
                as_org="AKAMAI-ASN1 - Akamai International B.V., NL")
    ids = _ids(_posture(host=[ip]))
    assert "host_physical_extra_eu" in ids       # IP geolocates to the US
    assert "host_jurisdiction_extra_eu" not in ids  # ASN registered in NL
