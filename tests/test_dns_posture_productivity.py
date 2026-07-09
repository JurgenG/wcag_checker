"""Tests for the productivity-suite OSINT probes (Microsoft 365 + Google Workspace).

Each probe queries a fixed set of subdomains of the target domain and
classifies the CNAME / TXT response. Tests substitute a fake resolver
via monkeypatch so they exercise the classification logic without
hitting live DNS.
"""

from __future__ import annotations

import pytest

from leak_inspector.dns_posture import productivity


def _install_fake_resolver(
    monkeypatch: pytest.MonkeyPatch,
    *,
    cname_map: dict[str, list[str]] | None = None,
    txt_map: dict[str, list[str]] | None = None,
) -> None:
    """Replace ``productivity``'s resolver imports with dict-driven fakes."""
    cname_map = cname_map or {}
    txt_map = txt_map or {}
    monkeypatch.setattr(
        productivity, "query_cname",
        lambda name: list(cname_map.get(name.lower(), [])),
    )
    monkeypatch.setattr(
        productivity, "query_txt",
        lambda name: list(txt_map.get(name.lower(), [])),
    )


# --- Microsoft 365 CNAME probes --------------------------------------------


def test_m365_autodiscover_detected(monkeypatch) -> None:
    """``autodiscover.<domain>`` pointing to autodiscover.outlook.com → M365."""
    _install_fake_resolver(monkeypatch, cname_map={
        "autodiscover.example.be": ["autodiscover.outlook.com"],
    })
    probes = productivity.probe_m365(domain="example.be")
    labels = {p.label for p in probes}
    assert any("autodiscover" in lbl.lower() for lbl in labels)
    assert all(p.vendor == "Microsoft 365" for p in probes)


@pytest.mark.parametrize(
    "subname,expected_target,description_word",
    [
        ("lyncdiscover",          "webdir.online.lync.com",                       "teams"),
        ("sip",                   "sipdir.online.lync.com",                       "sip"),
        ("enterpriseregistration","enterpriseregistration.windows.net",           "entra"),
        ("enterpriseenrollment",  "enterpriseenrollment.manage.microsoft.com",    "intune"),
    ],
)
def test_m365_individual_cname_probes(
    monkeypatch, subname: str, expected_target: str, description_word: str,
) -> None:
    _install_fake_resolver(monkeypatch, cname_map={
        f"{subname}.example.be": [expected_target],
    })
    probes = productivity.probe_m365(domain="example.be")
    matching = [
        p for p in probes
        if p.subdomain == f"{subname}.example.be"
    ]
    assert matching, f"no probe fired for {subname}"
    p = matching[0]
    assert p.vendor == "Microsoft 365"
    assert p.signal_type == "cname"
    assert p.target == expected_target
    assert description_word in p.label.lower()


def test_m365_dkim_selectors_reveal_tenant_name(monkeypatch) -> None:
    """The DKIM CNAME target reveals the M365 tenant name (<tenant>.onmicrosoft.com)."""
    _install_fake_resolver(monkeypatch, cname_map={
        "selector1._domainkey.example.be":
            ["selector1-example-be._domainkey.exampleorg.onmicrosoft.com"],
        "selector2._domainkey.example.be":
            ["selector2-example-be._domainkey.exampleorg.onmicrosoft.com"],
    })
    probes = productivity.probe_m365(domain="example.be")
    dkim_probes = [p for p in probes if p.signal_type == "dkim_cname"]
    assert len(dkim_probes) == 2
    # Tenant name is observable in the target
    for p in dkim_probes:
        assert "exampleorg.onmicrosoft.com" in p.target


def test_m365_no_match_does_not_false_positive(monkeypatch) -> None:
    """A CNAME target outside the M365 family does NOT produce a probe."""
    _install_fake_resolver(monkeypatch, cname_map={
        "autodiscover.example.be": ["mail.exchange.example-self-hosted.be"],
    })
    probes = productivity.probe_m365(domain="example.be")
    assert probes == []


def test_m365_missing_subdomain_silent(monkeypatch) -> None:
    """When no CNAMEs exist, the probe returns an empty list (no errors)."""
    _install_fake_resolver(monkeypatch)
    assert productivity.probe_m365(domain="example.be") == []


# --- Google Workspace CNAME probes -----------------------------------------


@pytest.mark.parametrize(
    "subname",
    ["mail", "calendar", "drive", "docs", "sites"],
)
def test_workspace_branded_url_cnames(monkeypatch, subname: str) -> None:
    _install_fake_resolver(monkeypatch, cname_map={
        f"{subname}.example.be": ["ghs.googlehosted.com"],
    })
    probes = productivity.probe_workspace(domain="example.be")
    matching = [p for p in probes if p.subdomain == f"{subname}.example.be"]
    assert matching, f"no Workspace probe fired for {subname}"
    p = matching[0]
    assert p.vendor == "Google Workspace"
    assert p.signal_type == "cname"
    assert "ghs.googlehosted.com" in p.target


def test_workspace_dkim_via_txt(monkeypatch) -> None:
    """google._domainkey TXT containing v=DKIM1 confirms Workspace DKIM."""
    _install_fake_resolver(
        monkeypatch,
        txt_map={
            "google._domainkey.example.be": [
                "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA…"
            ],
        },
    )
    probes = productivity.probe_workspace(domain="example.be")
    dkim_probes = [p for p in probes if p.signal_type == "dkim_txt"]
    assert len(dkim_probes) == 1
    assert dkim_probes[0].subdomain == "google._domainkey.example.be"


def test_workspace_no_match_does_not_false_positive(monkeypatch) -> None:
    """A CNAME to something other than ghs.googlehosted.com does NOT fire."""
    _install_fake_resolver(monkeypatch, cname_map={
        "mail.example.be": ["mail.example-self-hosted.be"],
    })
    probes = productivity.probe_workspace(domain="example.be")
    assert probes == []


def test_workspace_missing_subdomain_silent(monkeypatch) -> None:
    _install_fake_resolver(monkeypatch)
    assert productivity.probe_workspace(domain="example.be") == []


# --- Combined `probe_all` --------------------------------------------------


def test_probe_all_returns_combined(monkeypatch) -> None:
    """``probe_all`` should fire both M365 and Workspace probes against ``domain``."""
    _install_fake_resolver(monkeypatch, cname_map={
        "autodiscover.example.be": ["autodiscover.outlook.com"],
        "mail.example.be": ["ghs.googlehosted.com"],
    })
    probes = productivity.probe_all(domain="example.be")
    vendors = {p.vendor for p in probes}
    assert vendors == {"Microsoft 365", "Google Workspace"}
