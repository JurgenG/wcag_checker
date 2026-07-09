"""Tests for the NIS2 / CCB CyberFundamentals baseline view (data only).

The view re-groups the already-collected posture facts into
operator-facing control areas, each tagged with its NIS2 Art. 21(2)
measure, and reports each control as ok / fail / not deployed / not
assessed. These tests pin the *data* (grouping, status verdicts, the
certainty rule), not any rendering — the renderers are exercised by the
report-format tests.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis, analyze_bundle
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.report.nis2 import (
    STATUS_FAIL,
    STATUS_NOT_ASSESSED,
    STATUS_NOT_DEPLOYED,
    STATUS_OK,
    build_cyberfundamentals_view,
)
from tests.fixtures.bundles import path as bundle_path


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://x.be/", base_domain="x.be",
        browser={}, profile="p", landing_url="https://x.be/",
    )


def _status(view, area_name: str, label: str) -> str:
    area = next(a for a in view.areas if a.name == area_name)
    return next(c for c in area.checks if c.label == label).status


# --- shape -------------------------------------------------------------------


def test_unenriched_capture_yields_no_view() -> None:
    """No posture data at all → None, so renderers stay silent."""
    assert build_cyberfundamentals_view(Analysis(manifest=_manifest())) is None


def test_areas_are_the_five_control_areas_in_order() -> None:
    view = build_cyberfundamentals_view(analyze_bundle(bundle_path("brecht.zip")))
    assert [a.name for a in view.areas] == [
        "Encryption in transit",
        "Email security",
        "DNS security & resilience",
        "Web hardening",
        "Vulnerability disclosure",
    ]
    # each area is tagged with its NIS2 measure
    assert all(a.nis2.startswith("Art. 21(2)") for a in view.areas)


# --- certainty rule: un-probed data is "not assessed", never "fail" ----------


def test_unprobed_controls_report_not_assessed() -> None:
    """brecht's fixture predates the TLS + security.txt probes (both
    None) → those controls report not_assessed, not a false fail."""
    view = build_cyberfundamentals_view(analyze_bundle(bundle_path("brecht.zip")))
    assert _status(view, "Encryption in transit", "TLS certificate valid") \
        == STATUS_NOT_ASSESSED
    assert _status(view, "Vulnerability disclosure", "security.txt (RFC 9116)") \
        == STATUS_NOT_ASSESSED


# --- verdicts match the corpus facts -----------------------------------------


def test_brecht_email_and_dns_verdicts() -> None:
    """brecht: SPF ~all (ok), DMARC none (fail), no MTA-STS (fail),
    no CAA (fail), DNSSEC + >=2 NS."""
    view = build_cyberfundamentals_view(analyze_bundle(bundle_path("brecht.zip")))
    assert _status(view, "Email security", "SPF restricts senders") == STATUS_OK
    assert _status(view, "Email security", "DMARC enforced") == STATUS_FAIL
    assert _status(view, "Email security", "MTA-STS policy") == STATUS_FAIL
    assert _status(view, "DNS security & resilience", "CAA record") == STATUS_FAIL
    assert _status(view, "DNS security & resilience",
                   "Two or more nameservers") == STATUS_OK


def test_nbb_publishes_caa_and_mta_sts() -> None:
    """nbb is the email-hygiene exemplar: CAA + MTA-STS both present."""
    view = build_cyberfundamentals_view(analyze_bundle(bundle_path("nbb.zip")))
    assert _status(view, "Email security", "MTA-STS policy") == STATUS_OK
    assert _status(view, "DNS security & resilience", "CAA record") == STATUS_OK


def test_tls_rpt_is_surface_only_not_a_failure() -> None:
    """No fixture publishes TLS-RPT; with mail present it reports
    not_deployed (an optional add-on), never fail."""
    view = build_cyberfundamentals_view(analyze_bundle(bundle_path("brecht.zip")))
    assert _status(view, "Email security", "TLS-RPT reporting") \
        == STATUS_NOT_DEPLOYED


def test_mta_sts_and_tls_rpt_not_assessed_without_mx() -> None:
    """A domain that publishes no MX is not penalised for inbound-mail
    controls — both report not_assessed."""
    from leak_inspector.dns_posture.types import DNSPosture

    analysis = Analysis(
        manifest=_manifest(),
        dns_posture=DNSPosture(domain="x.be", looked_up_at="t", mx=[]),
    )
    view = build_cyberfundamentals_view(analysis)
    assert _status(view, "Email security", "MTA-STS policy") == STATUS_NOT_ASSESSED
    assert _status(view, "Email security", "TLS-RPT reporting") \
        == STATUS_NOT_ASSESSED


def test_view_is_wired_into_the_document_and_json() -> None:
    """build_report_document carries the view, and it round-trips to JSON."""
    import json

    from leak_inspector.report.builder import build_report_document
    from leak_inspector.report.json_reporter import write_document_json

    doc = build_report_document(analyze_bundle(bundle_path("brecht.zip")))
    assert doc.cyberfundamentals is not None
    payload = json.loads(write_document_json(doc))
    assert len(payload["cyberfundamentals"]["areas"]) == 5
    assert payload["cyberfundamentals"]["assessed"] >= 1


def test_assessed_and_passed_counts_exclude_unassessed_and_surface_only() -> None:
    view = build_cyberfundamentals_view(analyze_bundle(bundle_path("brecht.zip")))
    all_checks = [c for a in view.areas for c in a.checks]
    expected_assessed = sum(
        1 for c in all_checks if c.status in (STATUS_OK, STATUS_FAIL)
    )
    expected_passed = sum(1 for c in all_checks if c.status == STATUS_OK)
    assert view.assessed == expected_assessed
    assert view.passed == expected_passed
    # surface-only / un-assessed never inflate the denominator
    assert view.assessed < len(all_checks)