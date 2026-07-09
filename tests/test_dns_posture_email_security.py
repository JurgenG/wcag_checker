"""Tests for the email-security vendor classifiers (SPF + MX).

The SPF classifier is exercised indirectly via the email_security spec
elsewhere; this file focuses on the new MX-hostname classifier added
alongside the productivity-suite work.
"""

from __future__ import annotations

import pytest

from leak_inspector.dns_posture.email_security import classify_mx_vendor


# --- Microsoft 365 -----------------------------------------------------------


@pytest.mark.parametrize(
    "hostname",
    [
        # Standard tenant-named MX shape: <domain-tag>.mail.protection.outlook.com
        "example-be.mail.protection.outlook.com",
        "acme-com.mail.protection.outlook.com",
        # Trailing dot stripped form (resolvers strip trailing dots already)
        "veurne-be.mail.protection.outlook.com",
        # Generic suffix should also match
        "mail.protection.outlook.com",
    ],
)
def test_mx_classifies_microsoft_365(hostname: str) -> None:
    assert classify_mx_vendor(hostname) == "Microsoft 365 (Exchange Online)"


# --- Google Workspace --------------------------------------------------------


@pytest.mark.parametrize(
    "hostname",
    [
        "aspmx.l.google.com",
        "alt1.aspmx.l.google.com",
        "alt2.aspmx.l.google.com",
        "alt3.aspmx.l.google.com",
        "alt4.aspmx.l.google.com",
        "aspmx2.googlemail.com",
        "aspmx3.googlemail.com",
        "aspmx4.googlemail.com",
        "aspmx5.googlemail.com",
    ],
)
def test_mx_classifies_google_workspace(hostname: str) -> None:
    assert classify_mx_vendor(hostname) == "Google Workspace / Gmail"


# --- Other recognised providers ---------------------------------------------


@pytest.mark.parametrize(
    "hostname,expected",
    [
        ("mail.protonmail.ch",        "Proton Mail"),
        ("mailsec.protonmail.ch",     "Proton Mail"),
        ("in1-smtp.messagingengine.com", "Fastmail"),
        ("mx.zoho.com",               "Zoho Mail"),
        ("mx.zoho.eu",                "Zoho Mail"),
        ("mxa.mailbox.org",           "mailbox.org"),
        ("mxb.mailbox.org",           "mailbox.org"),
    ],
)
def test_mx_classifies_other_providers(hostname: str, expected: str) -> None:
    assert classify_mx_vendor(hostname) == expected


# --- Negative cases ----------------------------------------------------------


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "mail.example.be",
        "smtp.example.be",
        "in.example-municipality.be",
        "outlook.example.com",          # plausible decoy — must not match
        "googlemail.example.com",       # plausible decoy — must not match
    ],
)
def test_mx_returns_empty_for_unknown(hostname: str) -> None:
    assert classify_mx_vendor(hostname) == ""


def test_case_insensitive() -> None:
    """MX hostnames sometimes come back upper-case from resolvers."""
    assert classify_mx_vendor(
        "EXAMPLE-BE.MAIL.PROTECTION.OUTLOOK.COM"
    ) == "Microsoft 365 (Exchange Online)"
