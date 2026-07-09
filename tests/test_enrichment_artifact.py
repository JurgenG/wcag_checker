"""Round-trip tests for the enrichment artifact (pipeline-split Phase 1).

The artifact is the JSON ``enrichment.json`` entry stored inside the
capture zip: everything the live network once contributed at
analysis time (DNS posture, transport posture, CMS version probe,
per-host IP/ASN/geo info), captured once at enrichment time so
analysis and reporting work fully offline afterwards.

Every test here is hermetic — objects in, JSON, objects out — and the
round-trips must be *exact* (dataclass equality), because the offline
analysis consumes the deserialized objects through the same seams the
live lookups used to fill.
"""

from __future__ import annotations

import json

import pytest

from leak_inspector.dns_posture.productivity import ProductivityProbe
from leak_inspector.dns_posture.types import (
    BIMIRecord,
    CAARecord,
    DKIMSelector,
    DMARCRecord,
    DNSPosture,
    DNSSECStatus,
    HTTPSRecord,
    HostRecord,
    IPInfo,
    MTASTSStatus,
    NameserverRecord,
    SPFRecord,
    TLSRPTStatus,
    TXTVerification,
)
from leak_inspector.enrichment.artifact import (
    ENRICHMENT_SECTIONS,
    ENRICHMENT_VERSION,
    ENRICHMENT_ZIP_ENTRY,
    CMSVersionProbe,
    Enrichment,
    enrichment_from_json,
    enrichment_to_json,
)
from leak_inspector.http_posture.probe import HostProbe, TransportPosture
from leak_inspector.http_posture.tls import TLSPosture


# --- builders: fully-populated objects, no field left at its default --------


def _ipinfo(address: str = "203.0.113.7") -> IPInfo:
    return IPInfo(
        address=address, version=4, asn=13335,
        as_org="Cloudflare, Inc.", country_code="US",
        country_name="United States", asn_country="US",
    )


def test_ipinfo_asn_country_round_trips() -> None:
    """The legal-jurisdiction field survives the artifact round-trip, and an
    old artifact lacking it deserialises to the empty default."""
    restored = enrichment_from_json(enrichment_to_json(_enrichment()))
    assert restored.dns_posture.a_records[0].asn_country == "US"

    import json
    blob = json.loads(enrichment_to_json(_enrichment()))
    del blob["dns_posture"]["a_records"][0]["asn_country"]
    reloaded = enrichment_from_json(json.dumps(blob))
    assert reloaded.dns_posture.a_records[0].asn_country == ""


def _dns_posture() -> DNSPosture:
    return DNSPosture(
        domain="example.be",
        looked_up_at="2026-06-07T12:00:00Z",
        geoip_available=True,
        a_records=[_ipinfo()],
        aaaa_records=[_ipinfo("2001:db8::7")],
        nameservers=[NameserverRecord(
            name="ns1.example.be", ips=[_ipinfo("203.0.113.53")],
            provider="Cloudflare",
        )],
        dnssec=DNSSECStatus(
            parent_has_ds=True, zone_has_dnskey=True, summary="signed",
        ),
        caa=CAARecord(
            raw_records=['0 issue "letsencrypt.org"'],
            issue_cas=["letsencrypt.org"], issuewild_cas=["none"],
        ),
        https=HTTPSRecord(
            present=True, alpn=["h2", "h3"], has_ech=True,
            raw_records=["1 . alpn=h2,h3"],
        ),
        mx=[HostRecord(
            name="mail.example.be", priority=10,
            ips=[_ipinfo("203.0.113.25")],
        )],
        spf=SPFRecord(
            raw="v=spf1 include:_spf.example.com -all",
            final_qualifier="-all", includes=["_spf.example.com"],
            a=["a.example.be"], mx=["mx.example.be"],
            redirect="r.example.be", sender_vendors=["Example Sender"],
        ),
        dmarc=DMARCRecord(
            raw="v=DMARC1; p=reject", policy="reject",
            subdomain_policy="quarantine", pct=90,
            rua=["mailto:agg@example.be"], ruf=["mailto:for@example.be"],
            report_processors=["example-processor"],
        ),
        dkim=[DKIMSelector(selector="s1", found=True, raw="v=DKIM1; k=rsa")],
        mta_sts=MTASTSStatus(txt_present=True, txt_id="20260607T000000"),
        tls_rpt=TLSRPTStatus(txt_present=True, rua=["mailto:tls@example.be"]),
        bimi=BIMIRecord(
            present=True, svg_url="https://example.be/b.svg",
            vmc_url="https://example.be/b.pem",
        ),
        txt_verifications=[TXTVerification(
            vendor="Google", purpose="Workspace / Search Console",
            jurisdiction="US",
        )],
        mail_providers=["Google Workspace / Gmail"],
        productivity_probes=[ProductivityProbe(
            label="Microsoft 365 (branded CNAME)", vendor="Microsoft 365",
            signal_type="cname", subdomain="autodiscover.example.be",
            target="autodiscover.outlook.com.",
        )],
        errors=["TXT lookup timed out once"],
    )


def _transport() -> TransportPosture:
    return TransportPosture(
        primary=HostProbe(
            host="www.example.be", http_responded=True,
            https_responded=True, http_status=301, https_status=200,
            http_final_url="https://www.example.be/",
            https_final_url="https://www.example.be/",
        ),
        alternate=HostProbe(
            host="example.be", http_responded=True,
            https_responded=False, http_status=200, https_status=None,
            http_final_url="http://example.be/", https_final_url=None,
        ),
    )


def _tls() -> TLSPosture:
    return TLSPosture(
        host="www.example.be", connected=True,
        protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
        cert_not_before="2026-06-01T00:00:00Z",
        cert_not_after="2026-09-01T00:00:00Z",
        days_until_expiry=71, issuer="Let's Encrypt", subject_cn="example.be",
        verify_error="", legacy_tls10="rejected", legacy_tls11="rejected",
    )


def _enrichment() -> Enrichment:
    return Enrichment(
        enriched_at="2026-06-07T12:00:05Z",
        section_timestamps={
            "dns": "2026-06-07T12:00:05Z",
            "transport": "2026-06-07T12:00:05Z",
            "tls": "2026-06-07T12:00:05Z",
            "cms-probe": "2026-06-19T09:30:00Z",
            "security-txt": "2026-06-07T12:00:05Z",
            "hosts": "2026-06-07T12:00:05Z",
        },
        dns_posture=_dns_posture(),
        transport_posture=_transport(),
        tls_posture=_tls(),
        cms_probe=CMSVersionProbe(
            platform="Drupal", version="10.2.1",
            probe_url="https://www.example.be/CHANGELOG.txt",
        ),
        host_ipinfo={
            "stats.example.be": _ipinfo("203.0.113.99"),
            "unresolvable.example": None,
        },
        errors=["transport probe of alternate timed out"],
    )


# --- identity ----------------------------------------------------------------


def test_zip_entry_name_and_version() -> None:
    assert ENRICHMENT_ZIP_ENTRY == "enrichment.json"
    assert ENRICHMENT_VERSION == 3


def test_canonical_section_ids() -> None:
    assert ENRICHMENT_SECTIONS == (
        "dns", "transport", "tls", "cms-probe", "security-txt", "hosts",
    )


def test_section_timestamps_round_trip() -> None:
    original = _enrichment()
    restored = enrichment_from_json(enrichment_to_json(original))
    assert restored.section_timestamps == original.section_timestamps


def test_v1_artifact_without_section_timestamps_loads_with_empty_map() -> None:
    """A v1 artifact predates per-section timestamps; the field defaults
    to an empty map so readers fall back to ``enriched_at``."""
    v1_json = json.dumps(
        {"version": 1, "enriched_at": "2026-06-07T12:00:05Z"}
    )
    restored = enrichment_from_json(v1_json)
    assert restored.section_timestamps == {}
    assert restored.enriched_at == "2026-06-07T12:00:05Z"


def test_default_enrichment_carries_version() -> None:
    assert Enrichment().version == ENRICHMENT_VERSION


# --- exact round-trips --------------------------------------------------------


def test_full_round_trip_is_exact() -> None:
    original = _enrichment()
    restored = enrichment_from_json(enrichment_to_json(original))
    assert restored == original


def test_dns_posture_round_trip_every_nested_type() -> None:
    original = Enrichment(dns_posture=_dns_posture())
    restored = enrichment_from_json(enrichment_to_json(original))
    assert restored.dns_posture == _dns_posture()
    # The nested objects are real dataclasses again, not dicts.
    assert isinstance(restored.dns_posture.dnssec, DNSSECStatus)
    assert isinstance(restored.dns_posture.mx[0].ips[0], IPInfo)
    assert isinstance(
        restored.dns_posture.productivity_probes[0], ProductivityProbe
    )


def test_transport_round_trip_preserves_properties() -> None:
    restored = enrichment_from_json(
        enrichment_to_json(Enrichment(transport_posture=_transport()))
    ).transport_posture
    assert restored == _transport()
    # Derived properties (used by the security score) still work.
    assert restored.primary.http_redirects_to_https is True
    assert restored.alternate.http_redirects_to_https is False


def test_host_ipinfo_round_trip_keeps_none_entries() -> None:
    restored = enrichment_from_json(enrichment_to_json(_enrichment()))
    assert restored.host_ipinfo["unresolvable.example"] is None
    assert restored.host_ipinfo["stats.example.be"] == _ipinfo("203.0.113.99")


def test_absent_sections_round_trip_as_none() -> None:
    original = Enrichment(enriched_at="2026-06-07T12:00:05Z")
    restored = enrichment_from_json(enrichment_to_json(original))
    assert restored == original
    assert restored.dns_posture is None
    assert restored.transport_posture is None
    assert restored.cms_probe is None
    assert restored.host_ipinfo == {}
    assert restored.security_txt is None
    assert restored.tls_posture is None


def test_tls_posture_round_trip_is_exact() -> None:
    restored = enrichment_from_json(
        enrichment_to_json(Enrichment(tls_posture=_tls()))
    ).tls_posture
    assert restored == _tls()
    assert isinstance(restored, TLSPosture)


def test_artifact_without_tls_posture_reads_as_none() -> None:
    """Artifacts written before the TLS probe (v1/v2) stay readable."""
    restored = enrichment_from_json(
        '{"version": 2, "enriched_at": "2026-06-07T12:00:05Z"}'
    )
    assert restored.tls_posture is None


def test_security_txt_round_trip_is_exact() -> None:
    from leak_inspector.http_posture.security_txt import SecurityTxtProbe

    probe = SecurityTxtProbe(
        url="https://www.example.be/.well-known/security.txt",
        found=True, status=200,
        content_type="text/plain; charset=utf-8", has_contact=True,
    )
    restored = enrichment_from_json(
        enrichment_to_json(Enrichment(security_txt=probe))
    ).security_txt
    assert restored == probe
    assert isinstance(restored, SecurityTxtProbe)


def test_artifact_without_security_txt_reads_as_none() -> None:
    """Artifacts written before the security.txt probe stay readable."""
    restored = enrichment_from_json(
        '{"version": 1, "enriched_at": "2026-06-07T12:00:05Z"}'
    )
    assert restored.security_txt is None


# --- forward / backward tolerance ---------------------------------------------


def test_unknown_top_level_keys_are_ignored() -> None:
    """A future enrichment version may add sections — old readers must
    not choke on them."""
    payload = json.loads(enrichment_to_json(_enrichment()))
    payload["some_future_section"] = {"x": 1}
    payload["dns_posture"]["some_future_field"] = "y"
    restored = enrichment_from_json(json.dumps(payload))
    assert restored == _enrichment()


def test_missing_optional_fields_take_defaults() -> None:
    """A minimal artifact (older writer) deserializes with defaults."""
    restored = enrichment_from_json(
        '{"version": 1, "enriched_at": "2026-06-07T12:00:05Z"}'
    )
    assert restored.enriched_at == "2026-06-07T12:00:05Z"
    assert restored.dns_posture is None
    assert restored.errors == []


def test_malformed_json_raises_value_error() -> None:
    with pytest.raises(ValueError):
        enrichment_from_json("{not json")
