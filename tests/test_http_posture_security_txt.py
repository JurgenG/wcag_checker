"""Tests for the RFC 9116 ``security.txt`` presence probe.

One well-known-path fetch at ``https://<host>/.well-known/security.txt``,
run in the enrichment phase. "Present" is a guarded claim (certain-data
rule): a soft-404 — an HTML error page served with status 200 — must not
count, so presence requires status 200 **and** a ``text/plain`` content
type **and** a ``Contact:`` field (the only field RFC 9116 REQUIRES).
The raw signals are recorded so reports can distinguish "absent" from
"present but malformed". All offline via the injected fetcher.
"""

from __future__ import annotations

import pytest

from leak_inspector.http_posture.security_txt import (
    SecurityTxtProbe,
    probe_security_txt,
)

_BODY_OK = (
    "Contact: mailto:security@example.be\n"
    "Expires: 2027-01-01T00:00:00.000Z\n"
)


def _fetcher(status, content_type="", body=""):
    def fetch(url: str):
        return status, content_type, body
    return fetch


def test_probes_the_well_known_url() -> None:
    seen: list[str] = []

    def fetch(url: str):
        seen.append(url)
        return 404, "", ""

    probe_security_txt("www.example.be", fetcher=fetch)
    assert seen == ["https://www.example.be/.well-known/security.txt"]


def test_valid_security_txt_is_found() -> None:
    probe = probe_security_txt("www.example.be", fetcher=_fetcher(
        200, "text/plain; charset=utf-8", _BODY_OK))
    assert probe == SecurityTxtProbe(
        url="https://www.example.be/.well-known/security.txt",
        found=True, status=200,
        content_type="text/plain; charset=utf-8", has_contact=True,
    )


def test_soft_404_html_page_is_not_found() -> None:
    """A 200 HTML error page (very common) must not count as present."""
    probe = probe_security_txt("www.example.be", fetcher=_fetcher(
        200, "text/html; charset=utf-8", "<html>Niet gevonden</html>"))
    assert probe.found is False
    assert probe.status == 200


def test_404_is_not_found_with_status_recorded() -> None:
    probe = probe_security_txt("www.example.be", fetcher=_fetcher(404, "", ""))
    assert probe.found is False
    assert probe.status == 404


def test_plain_text_without_contact_is_not_found() -> None:
    """``Contact:`` is the only REQUIRED field — a text/plain body
    without one is not a usable security.txt."""
    probe = probe_security_txt("www.example.be", fetcher=_fetcher(
        200, "text/plain", "# placeholder\n"))
    assert probe.found is False
    assert probe.has_contact is False


def test_contact_field_is_case_insensitive() -> None:
    probe = probe_security_txt("www.example.be", fetcher=_fetcher(
        200, "text/plain", "CONTACT: mailto:cert@example.be\n"))
    assert probe.found is True


def test_contact_must_start_a_line() -> None:
    """A mention of 'contact:' mid-prose is not the field."""
    probe = probe_security_txt("www.example.be", fetcher=_fetcher(
        200, "text/plain", "See our contact: page for details\n"))
    assert probe.found is False


def test_unreachable_host_records_no_status() -> None:
    probe = probe_security_txt("www.example.be", fetcher=_fetcher(None))
    assert probe.found is False
    assert probe.status is None


def test_fetcher_exception_soft_fails() -> None:
    def boom(url: str):
        raise OSError("connection refused")

    probe = probe_security_txt("www.example.be", fetcher=boom)
    assert probe.found is False
    assert probe.status is None


# --- single wording source for the report line -------------------------------


def test_line_present() -> None:
    from leak_inspector.report.text import _security_txt_line

    probe = SecurityTxtProbe(url="u", found=True, status=200,
                             content_type="text/plain", has_contact=True)
    line = _security_txt_line(probe)
    assert "security.txt" in line
    assert "published" in line


def test_line_absent() -> None:
    from leak_inspector.report.text import _security_txt_line

    line = _security_txt_line(SecurityTxtProbe(url="u", found=False, status=404))
    assert "security.txt" in line
    assert "not found" in line


def test_line_silent_without_probe() -> None:
    from leak_inspector.report.text import _security_txt_line

    assert _security_txt_line(None) is None
