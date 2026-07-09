"""Tests for the v2 deduction assembler (Scoring-v2 Phase 6a).

`build_deductions(analysis, modules_by_id)` turns one Analysis into the
full list of `Deduction` rows — module deductions (via effective_rating)
plus non-module signal deductions mapped from real analysis facts,
reusing the v1 predicates. The certainty rule governs the signals: a
posture signal fires only when the underlying data is present *and*
adverse, so an un-enriched bundle is never penalised for data we never
measured. Pinned against real fixtures.
"""

from __future__ import annotations

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector import signals  # noqa: F401  (registers signal ratings)
from leak_inspector.analysis.runner import Analysis, analyze_bundle
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.modules.base import all_modules
from leak_inspector.report.score_v2 import (
    build_deductions,
    compute_score_logistic,
)
from tests.fixtures.bundles import path as bundle_path


@pytest.fixture(scope="module")
def by_id():
    return {m.module_id: m for m in all_modules()}


def _ids(deductions, kind=None):
    return [d.source_id for d in deductions if kind is None or d.kind == kind]


# --- modules + signals combined ----------------------------------------------


def test_returns_modules_and_signals(by_id) -> None:
    analysis = analyze_bundle(bundle_path("doccle-reject.zip"))
    deductions, unrated = build_deductions(analysis, by_id)
    kinds = {d.kind for d in deductions}
    assert kinds == {"module", "signal"}
    assert unrated == []  # every fired module is rated after the sweep


def test_modules_come_through_with_variants(by_id) -> None:
    """doccle-reject's GA4 is the consent-denied variant (all gcs=G100)."""
    analysis = analyze_bundle(bundle_path("doccle-reject.zip"))
    deductions, _ = build_deductions(analysis, by_id)
    ga4 = next(d for d in deductions if d.source_id == "ga4")
    assert ga4.rating.privacy == 1.5


# --- server-sovereignty signals (physical + jurisdiction, per component) -----


def test_aalst_fires_host_and_mail_sovereignty(by_id) -> None:
    """aalst: Google-hosted (US) + M365 mail (US), DNS on Belgian Telenet."""
    sig = _ids(build_deductions(analyze_bundle(bundle_path("aalst.zip")), by_id)[0],
               "signal")
    assert "host_physical_extra_eu" in sig
    assert "host_jurisdiction_extra_eu" in sig
    assert "mail_physical_extra_eu" in sig
    assert "mail_jurisdiction_extra_eu" in sig
    assert "dns_physical_extra_eu" not in sig
    assert "dns_jurisdiction_extra_eu" not in sig


def test_nbb_fires_mail_and_dns_but_not_host(by_id) -> None:
    """nbb self-hosts (Belgian National Bank) but runs M365 mail + Azure DNS."""
    sig = _ids(build_deductions(analyze_bundle(bundle_path("nbb.zip")), by_id)[0],
               "signal")
    assert "host_physical_extra_eu" not in sig
    assert "host_jurisdiction_extra_eu" not in sig
    assert "mail_jurisdiction_extra_eu" in sig
    assert "dns_jurisdiction_extra_eu" in sig


def test_belgian_site_fires_no_sovereignty_signals(by_id) -> None:
    sig = _ids(build_deductions(analyze_bundle(bundle_path("brecht.zip")), by_id)[0],
               "signal")
    assert not any("extra_eu" in s for s in sig)


def test_kbc_fires_physical_only_for_eu_registered_akamai(by_id) -> None:
    """kbc on Akamai: the IPs geolocate to the US but the ASN is registered
    'Akamai International B.V., NL' — physical penalty, no jurisdiction one."""
    sig = _ids(build_deductions(analyze_bundle(bundle_path("kbc.zip")), by_id)[0],
               "signal")
    assert "host_physical_extra_eu" in sig
    assert "host_jurisdiction_extra_eu" not in sig


# --- consent compliance signals (one per offending vendor) -------------------


def test_doccle_reject_fires_post_reject_per_vendor(by_id) -> None:
    analysis = analyze_bundle(bundle_path("doccle-reject.zip"))
    deductions, _ = build_deductions(analysis, by_id)
    post = [d for d in deductions if d.source_id == "post_reject_tracking"]
    pre = [d for d in deductions if d.source_id == "pre_consent_tracking"]
    assert len(post) == len(analysis.consent.post_reject_vendors)
    assert len(pre) == len(analysis.consent.pre_decision_vendors)
    assert post  # at least one vendor kept tracking after the reject
    # the vendor name rides on the label for the rationale
    assert any("Clarity" in d.label for d in post)


def test_persistent_cookie_signal_fires_per_vendor(by_id) -> None:
    analysis = analyze_bundle(bundle_path("doccle-reject.zip"))
    deductions, _ = build_deductions(analysis, by_id)
    persistent = [d for d in deductions if d.source_id == "persistent_xs_cookie"]
    assert len(persistent) == 1  # doccle-reject has one persistent xs vendor


# --- certainty rule: no posture → no posture signals -------------------------


def test_unenriched_analysis_fires_no_posture_signals(by_id) -> None:
    """No transport / DNS / headers / security.txt observed → none of the
    posture signals fire (we never penalise un-measured data)."""
    manifest = Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://x.be/", base_domain="x.be",
        browser={}, profile="p", landing_url="https://x.be/",
    )
    analysis = Analysis(manifest=manifest)
    sig = _ids(build_deductions(analysis, by_id)[0], "signal")
    for posture_signal in (
        "https_broken", "no_https_redirect", "hsts_missing", "csp_missing",
        "xcto_missing", "xfo_missing", "referrer_policy_missing",
        "permissions_policy_missing", "dnssec_unsigned", "dmarc_weak",
        "host_physical_extra_eu", "host_jurisdiction_extra_eu",
        "mail_physical_extra_eu", "mail_jurisdiction_extra_eu",
        "dns_physical_extra_eu", "dns_jurisdiction_extra_eu",
        "security_txt_missing", "eol_platform",
        "tls_cert_invalid", "tls_legacy_protocol", "tls_cert_expiring_soon",
        "spf_weak", "caa_missing", "mta_sts_missing", "dns_single_nameserver",
    ):
        assert posture_signal not in sig, posture_signal


# --- TLS-quality signals (certain-data rule) ---------------------------------


def _analysis_with_tls(**tls_kw):
    from leak_inspector.http_posture.tls import TLSPosture

    manifest = Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://x.be/", base_domain="x.be",
        browser={}, profile="p", landing_url="https://x.be/",
    )
    base = dict(
        host="x.be", connected=True, protocol="TLSv1.3", verify_error="",
        days_until_expiry=90, legacy_tls10="rejected", legacy_tls11="rejected",
    )
    base.update(tls_kw)
    return Analysis(manifest=manifest, tls_posture=TLSPosture(**base))


def test_clean_tls_fires_no_tls_signal(by_id) -> None:
    sig = _ids(build_deductions(_analysis_with_tls(), by_id)[0], "signal")
    assert "tls_cert_invalid" not in sig
    assert "tls_legacy_protocol" not in sig
    assert "tls_cert_expiring_soon" not in sig


def test_invalid_cert_fires_tls_cert_invalid(by_id) -> None:
    a = _analysis_with_tls(verify_error="certificate has expired")
    sig = _ids(build_deductions(a, by_id)[0], "signal")
    assert "tls_cert_invalid" in sig
    # Invalid chain dominates — no expiry double-count.
    assert "tls_cert_expiring_soon" not in sig


def test_accepted_legacy_fires_signal_but_rejected_and_untestable_do_not(by_id) -> None:
    accepted = _ids(
        build_deductions(_analysis_with_tls(legacy_tls10="accepted"), by_id)[0],
        "signal",
    )
    assert "tls_legacy_protocol" in accepted
    for state in ("rejected", "untestable"):
        sig = _ids(
            build_deductions(_analysis_with_tls(legacy_tls11=state), by_id)[0],
            "signal",
        )
        assert "tls_legacy_protocol" not in sig


def test_expiring_soon_fires_only_within_window(by_id) -> None:
    soon = _ids(build_deductions(_analysis_with_tls(days_until_expiry=7), by_id)[0],
                "signal")
    assert "tls_cert_expiring_soon" in soon
    far = _ids(build_deductions(_analysis_with_tls(days_until_expiry=60), by_id)[0],
               "signal")
    assert "tls_cert_expiring_soon" not in far


def test_unreachable_tls_fires_no_tls_signal(by_id) -> None:
    """A host that doesn't speak TLS is the transport layer's HTTPS-broken
    concern, not a TLS-quality signal."""
    sig = _ids(build_deductions(_analysis_with_tls(connected=False), by_id)[0],
               "signal")
    assert "tls_cert_invalid" not in sig
    assert "tls_legacy_protocol" not in sig


def test_security_txt_absent_does_not_fire_when_unprobed(by_id) -> None:
    """The fixtures predate the security.txt probe (security_txt is None)
    → no signal, rather than a false 'missing'."""
    analysis = analyze_bundle(bundle_path("nbb.zip"))
    sig = _ids(build_deductions(analysis, by_id)[0], "signal")
    assert "security_txt_missing" not in sig


def test_eol_platform_signal_fires_for_eol_fingerprint(by_id) -> None:
    """An end-of-life platform fires the heavy eol_platform security
    signal (the v1 EOL-cap behaviour, now a deduction)."""
    from dataclasses import dataclass

    @dataclass
    class _FP:
        name: str = "Drupal"
        version: str = "7"
        is_eol: bool = True

    analysis = analyze_bundle(bundle_path("nbb.zip"))
    analysis.cms_fingerprint = _FP()
    sig = _ids(build_deductions(analysis, by_id)[0], "signal")
    assert "eol_platform" in sig


# --- NIS2 / CyberFundamentals email + DNS signals ----------------------------


def _analysis_with_dns(**dns_kw):
    """Build an Analysis carrying a synthetic DNSPosture for the email/DNS
    posture signals (SPF / CAA / MTA-STS / nameserver count)."""
    from leak_inspector.dns_posture.types import DNSPosture

    manifest = Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://x.be/", base_domain="x.be",
        browser={}, profile="p", landing_url="https://x.be/",
    )
    base: dict = dict(domain="x.be", looked_up_at="t")
    base.update(dns_kw)
    return Analysis(manifest=manifest, dns_posture=DNSPosture(**base))


def test_spf_weak_fires_on_missing_or_pass_all(by_id) -> None:
    from leak_inspector.dns_posture.types import SPFRecord

    # missing SPF
    missing = _ids(build_deductions(_analysis_with_dns(spf=None), by_id)[0], "signal")
    assert "spf_weak" in missing
    # +all (passes everything) is weak
    passall = _ids(build_deductions(
        _analysis_with_dns(spf=SPFRecord(raw="v=spf1 +all", final_qualifier="+all")),
        by_id)[0], "signal")
    assert "spf_weak" in passall


def test_spf_hardfail_and_softfail_do_not_fire(by_id) -> None:
    from leak_inspector.dns_posture.types import SPFRecord

    for qualifier in ("-all", "~all"):
        sig = _ids(build_deductions(
            _analysis_with_dns(
                spf=SPFRecord(raw=f"v=spf1 {qualifier}", final_qualifier=qualifier)),
            by_id)[0], "signal")
        assert "spf_weak" not in sig, qualifier


def test_caa_missing_fires_on_absent_only(by_id) -> None:
    """brecht publishes no CAA → fires; aalst publishes CAA → does not."""
    brecht = _ids(build_deductions(analyze_bundle(bundle_path("brecht.zip")), by_id)[0],
                  "signal")
    aalst = _ids(build_deductions(analyze_bundle(bundle_path("aalst.zip")), by_id)[0],
                 "signal")
    assert "caa_missing" in brecht
    assert "caa_missing" not in aalst


def test_mta_sts_missing_fires_only_when_mail_present(by_id) -> None:
    """brecht receives mail but has no MTA-STS → fires; nbb publishes one →
    does not; a no-MX domain is never penalised (inbound-only control)."""
    from leak_inspector.dns_posture.types import HostRecord, MTASTSStatus

    brecht = _ids(build_deductions(analyze_bundle(bundle_path("brecht.zip")), by_id)[0],
                  "signal")
    nbb = _ids(build_deductions(analyze_bundle(bundle_path("nbb.zip")), by_id)[0],
               "signal")
    assert "mta_sts_missing" in brecht
    assert "mta_sts_missing" not in nbb
    # no MX → not applicable, never fires
    no_mail = _ids(build_deductions(_analysis_with_dns(mx=[]), by_id)[0], "signal")
    assert "mta_sts_missing" not in no_mail
    # present policy → does not fire
    has_policy = _ids(build_deductions(_analysis_with_dns(
        mx=[HostRecord(name="mx.x.be", priority=10)],
        mta_sts=MTASTSStatus(txt_present=True, txt_id="v=STSv1; id=1")),
        by_id)[0], "signal")
    assert "mta_sts_missing" not in has_policy


def test_dns_single_nameserver_fires_only_on_exactly_one(by_id) -> None:
    from leak_inspector.dns_posture.types import NameserverRecord

    one = _ids(build_deductions(_analysis_with_dns(
        nameservers=[NameserverRecord(name="ns1.x.be")]), by_id)[0], "signal")
    assert "dns_single_nameserver" in one
    two = _ids(build_deductions(_analysis_with_dns(
        nameservers=[NameserverRecord(name="ns1.x.be"),
                     NameserverRecord(name="ns2.x.be")]), by_id)[0], "signal")
    assert "dns_single_nameserver" not in two
    # zero nameservers = not measured, not "single" — certain-data rule
    none = _ids(build_deductions(_analysis_with_dns(nameservers=[]), by_id)[0],
                "signal")
    assert "dns_single_nameserver" not in none


# --- end-to-end through the logistic model -----------------------------------


def test_build_then_score_runs_end_to_end(by_id) -> None:
    analysis = analyze_bundle(bundle_path("nbb.zip"))
    deductions, _ = build_deductions(analysis, by_id)
    score = compute_score_logistic(deductions)
    assert 0.0 <= score.total <= 100.0
    # security now carries signal penalties too (headers / DNS), so it is
    # no longer module-only.
    assert score.security.penalty > 0


def test_score_view_carries_raw_total_consistent_with_display(by_id) -> None:
    """The view exposes the un-ceiled raw total used for exact ranking,
    and it ceils to the displayed integer."""
    import math

    from leak_inspector.report.score_v2 import build_score_view

    view = build_score_view(analyze_bundle(bundle_path("nbb.zip")), by_id)
    assert view is not None
    assert isinstance(view.raw_total, float)
    assert math.ceil(view.raw_total) == view.total


# --- the report-facing view: ceil display + per-detail breakdown -------------


def test_doccle_reject_view_prints_1_not_0() -> None:
    """The catastrophic-privacy site ceils to 1, never 0 (the raw score
    is a tiny positive number, not a true zero)."""
    from leak_inspector.report.score_v2 import build_score_view
    from leak_inspector.modules.base import all_modules

    by_id = {m.module_id: m for m in all_modules()}
    view = build_score_view(
        analyze_bundle(bundle_path("doccle-reject.zip")), by_id,
    )
    assert view.privacy.stars == 1
    assert view.total >= 1


def test_view_dimension_itemises_every_penalty() -> None:
    """Each dimension carries the full (detail, penalty) list the
    detailed report prints — not just the top-three rationale."""
    from leak_inspector.report.score_v2 import build_score_view
    from leak_inspector.modules.base import all_modules

    by_id = {m.module_id: m for m in all_modules()}
    view = build_score_view(
        analyze_bundle(bundle_path("doccle-reject.zip")), by_id,
    )
    labels = [line.label for line in view.privacy.deductions]
    # the consent signals appear per vendor, with their penalty
    assert any("after reject" in lbl for lbl in labels)
    assert "Microsoft Clarity" in labels
    # more details than the 3 named in the summary rationale
    assert len(view.privacy.deductions) > 3
    # the >1 penalties carry an explainer string
    assert any(
        line.explainer for line in view.privacy.deductions if line.amount > 1.0
    )
