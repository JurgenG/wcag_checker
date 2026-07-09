# leak_inspector — record what data a website leaks during a real
# human-driven browsing session.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""NIS2 / CCB CyberFundamentals baseline view.

A presentation layer over the posture facts the analysis already
carries: it re-groups the externally-observable technical controls into
the operator-facing areas one acts on (encryption in transit, email
security, DNS security, web hardening, vulnerability disclosure), tags
each area with the NIS2 Art. 21(2) measure it serves, and reports each
control as ``ok`` / ``fail`` / ``not deployed`` / ``not assessed``.

This is an **indicator**, not a conformity assessment: NIS2 and the CCB
CyberFundamentals framework are mostly organizational (incident
handling, business continuity, HR security, training), none of which is
visible from a browsing capture. Only the technical baseline is
observable, and that is all this view claims.

The certainty rule governs every row: a control whose underlying data
was never captured (no transport probe, no DNS lookup, no header
observation) reports ``not assessed`` — never ``fail``. The pass/fail
verdicts reuse the same predicates the score signals key on
(:mod:`leak_inspector.report.score_v2`), so the baseline view and the
scorecard never disagree.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..http_posture.findings import CERT_EXPIRY_WARN_DAYS
from .score_v2 import (
    _SPF_ACCEPTABLE_QUALIFIERS,
    _csp_present,
    _DMARC_STRICT_POLICIES,
    _hsts_present,
    _permissions_policy_present,
    _referrer_policy_present,
    _xcto_present,
    _xfo_present,
)

#: A control passes / fails / is an optional control left undeployed /
#: could not be evaluated because the data was not captured.
STATUS_OK = "ok"
STATUS_FAIL = "fail"
STATUS_NOT_DEPLOYED = "not_deployed"
STATUS_NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class ControlCheck:
    """One observable control: its label, status, and (on a miss) a short
    operator-facing detail string."""

    label: str
    status: str
    detail: str = ""


@dataclass(frozen=True)
class ControlArea:
    """A group of related controls, tagged with the NIS2 Art. 21(2)
    measure(s) it serves (e.g. ``"Art. 21(2)(h)"``)."""

    name: str
    nis2: str
    checks: tuple[ControlCheck, ...]


@dataclass(frozen=True)
class CyberFundamentalsView:
    """The full NIS2 / CyberFundamentals baseline for one capture.

    ``assessed`` counts the controls that could be evaluated (``ok`` or
    ``fail``); ``passed`` is how many of those passed. ``not deployed``
    (optional surface-only controls) and ``not assessed`` (un-probed
    data) are excluded from both, so the ratio reflects only what was
    actually measured.
    """

    areas: tuple[ControlArea, ...]
    assessed: int
    passed: int


def _check(label: str, *, assessed: bool, ok: bool,
           detail: str = "") -> ControlCheck:
    """A pass/fail control, or ``not assessed`` when its data is absent."""
    if not assessed:
        return ControlCheck(label, STATUS_NOT_ASSESSED)
    return ControlCheck(label, STATUS_OK if ok else STATUS_FAIL,
                        "" if ok else detail)


def _encryption_area(tp, sh, tls) -> ControlArea:
    tls_live = tls is not None and getattr(tls, "connected", False)
    checks = [
        _check(
            "HTTPS enforced",
            assessed=tp is not None,
            ok=bool(tp and tp.primary.https_responded
                    and tp.primary.http_redirects_to_https),
            detail="HTTP is not redirected to HTTPS — a downgrade/MITM "
                   "opening.",
        ),
        _check(
            "HSTS", assessed=sh is not None, ok=_hsts_present(sh),
            detail="No Strict-Transport-Security header — first-visit "
                   "downgrade window.",
        ),
        _check(
            "TLS certificate valid", assessed=tls_live,
            ok=not getattr(tls, "verify_error", ""),
            detail="The certificate chain does not validate — the "
                   "connection is interceptable.",
        ),
        _check(
            "Modern TLS (no 1.0/1.1)", assessed=tls_live,
            ok="accepted" not in (getattr(tls, "legacy_tls10", ""),
                                  getattr(tls, "legacy_tls11", "")),
            detail="A deprecated TLS 1.0/1.1 version is still accepted.",
        ),
    ]
    return ControlArea("Encryption in transit", "Art. 21(2)(h)",
                       tuple(checks))


def _email_area(dp) -> ControlArea:
    has_mail = bool(dp and dp.mx)
    spf_ok = bool(dp and dp.spf
                  and (dp.spf.final_qualifier or "")
                  in _SPF_ACCEPTABLE_QUALIFIERS)
    dmarc_ok = bool(dp and dp.dmarc and (dp.dmarc.policy or "").lower()
                    in _DMARC_STRICT_POLICIES)
    checks = [
        _check(
            "SPF restricts senders", assessed=dp is not None, ok=spf_ok,
            detail="No SPF record, or it ends in +all/?all (authorises "
                   "any sender).",
        ),
        _check(
            "DMARC enforced", assessed=dp is not None, ok=dmarc_ok,
            detail="No DMARC policy of quarantine/reject — the domain is "
                   "spoofable.",
        ),
        # MTA-STS and TLS-RPT are inbound-mail controls: only meaningful
        # when the domain publishes an MX. A no-mail domain reports
        # "not assessed", never a failure.
        _check(
            "MTA-STS policy", assessed=has_mail,
            ok=bool(dp and dp.mta_sts and dp.mta_sts.txt_present),
            detail="No MTA-STS policy — inbound SMTP can be downgraded to "
                   "cleartext.",
        ),
        _tls_rpt_check(dp, has_mail),
    ]
    return ControlArea("Email security", "Art. 21(2)(g)/(h)", tuple(checks))


def _tls_rpt_check(dp, has_mail: bool) -> ControlCheck:
    """TLS-RPT is surface-only: present → ok, absent → ``not deployed``
    (a reporting add-on, not a hardening failure)."""
    if not has_mail:
        return ControlCheck("TLS-RPT reporting", STATUS_NOT_ASSESSED)
    present = bool(dp and dp.tls_rpt and dp.tls_rpt.txt_present)
    return ControlCheck(
        "TLS-RPT reporting",
        STATUS_OK if present else STATUS_NOT_DEPLOYED,
        "" if present else "Optional SMTP-TLS failure reporting is not "
                           "configured.",
    )


def _dns_area(dp) -> ControlArea:
    ns_count = len(dp.nameservers) if dp else 0
    checks = [
        _check(
            "DNSSEC signed",
            assessed=bool(dp and dp.dnssec is not None),
            ok=bool(dp and dp.dnssec and dp.dnssec.parent_has_ds
                    and dp.dnssec.zone_has_dnskey),
            detail="The zone is not DNSSEC-signed — responses can be "
                   "spoofed.",
        ),
        _check(
            "CAA record", assessed=dp is not None,
            ok=bool(dp and dp.caa and dp.caa.raw_records),
            detail="No CAA record — any public CA may issue a certificate "
                   "for the domain.",
        ),
        # Zero nameservers means the lookup did not resolve, not "single".
        _check(
            "Two or more nameservers", assessed=ns_count >= 1,
            ok=ns_count >= 2,
            detail="Only one authoritative nameserver — a resolution "
                   "single-point-of-failure (RFC 2182 wants two).",
        ),
    ]
    return ControlArea("DNS security & resilience", "Art. 21(2)(c)/(h)",
                       tuple(checks))


def _web_hardening_area(sh) -> ControlArea:
    assessed = sh is not None
    checks = [
        _check("Content-Security-Policy", assessed=assessed,
               ok=_csp_present(sh),
               detail="No enforcing CSP — the main XSS/injection mitigation "
                      "is absent."),
        _check("X-Frame-Options", assessed=assessed, ok=_xfo_present(sh),
               detail="No framing control — clickjacking opening."),
        _check("X-Content-Type-Options", assessed=assessed,
               ok=_xcto_present(sh),
               detail="No nosniff — MIME-sniffing opening."),
        _check("Referrer-Policy", assessed=assessed,
               ok=_referrer_policy_present(sh),
               detail="No Referrer-Policy — the full URL leaks to third "
                      "parties."),
        _check("Permissions-Policy", assessed=assessed,
               ok=_permissions_policy_present(sh),
               detail="No Permissions-Policy — powerful browser features "
                      "unrestricted."),
    ]
    return ControlArea("Web hardening", "Art. 21(2)(g)", tuple(checks))


def _vuln_disclosure_area(st, fp) -> ControlArea:
    checks = [
        _check(
            "security.txt (RFC 9116)", assessed=st is not None,
            ok=bool(getattr(st, "found", False)),
            detail="No machine-readable security contact for coordinated "
                   "vulnerability disclosure.",
        ),
        _check(
            "Supported platform (not end-of-life)", assessed=fp is not None,
            ok=not getattr(fp, "is_eol", False),
            detail="The site runs an end-of-life platform — known "
                   "vulnerabilities stay unpatched.",
        ),
    ]
    return ControlArea("Vulnerability disclosure", "Art. 21(2)(e)",
                       tuple(checks))


def build_cyberfundamentals_view(analysis) -> CyberFundamentalsView | None:
    """Assemble the NIS2 / CyberFundamentals baseline from an Analysis.

    Returns ``None`` when the capture carries no posture data at all (an
    un-enriched bundle), so renderers stay silent rather than printing a
    table of ``not assessed`` rows. Otherwise every area is present, with
    un-probed controls reported as ``not assessed`` per the certainty
    rule.
    """
    tp = getattr(analysis, "transport_posture", None)
    sh = getattr(analysis, "security_headers", None)
    dp = getattr(analysis, "dns_posture", None)
    tls = getattr(analysis, "tls_posture", None)
    st = getattr(analysis, "security_txt", None)
    fp = getattr(analysis, "cms_fingerprint", None)

    if all(x is None for x in (tp, sh, dp, tls, st, fp)):
        return None

    areas = (
        _encryption_area(tp, sh, tls),
        _email_area(dp),
        _dns_area(dp),
        _web_hardening_area(sh),
        _vuln_disclosure_area(st, fp),
    )
    all_checks = [c for area in areas for c in area.checks]
    assessed = sum(1 for c in all_checks
                   if c.status in (STATUS_OK, STATUS_FAIL))
    passed = sum(1 for c in all_checks if c.status == STATUS_OK)
    return CyberFundamentalsView(areas=areas, assessed=assessed,
                                 passed=passed)


__all__ = [
    "STATUS_OK",
    "STATUS_FAIL",
    "STATUS_NOT_DEPLOYED",
    "STATUS_NOT_ASSESSED",
    "ControlCheck",
    "ControlArea",
    "CyberFundamentalsView",
    "build_cyberfundamentals_view",
]