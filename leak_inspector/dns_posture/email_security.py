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

"""Email-security record parsers: SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT.

Each parser converts the raw TXT record(s) at a known location into a
structured dataclass from :mod:`.types`. SPF in particular is
recursively flattened: every ``include:`` is resolved one level deep
so the sender-vendor list in the resulting :class:`SPFRecord` reflects
the actual set of third parties allowed to mail on behalf of the
domain.
"""

from __future__ import annotations

import re

from .resolvers import query_txt
from .types import (
    BIMIRecord,
    DKIMSelector,
    DMARCRecord,
    MTASTSStatus,
    SPFRecord,
    TLSRPTStatus,
)


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------


#: SPF ``include:`` target hostname → human-readable sender-vendor label.
#: Match is suffix-based: ``mail.zendesk.com``, ``zendesk.com`` and
#: ``foo.zendesk.com`` all map to "Zendesk".
_SPF_VENDOR_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("_spf.google.com",            "Google Workspace / Gmail"),
    ("_googlemail.com",            "Google Workspace / Gmail"),
    ("spf.protection.outlook.com", "Microsoft 365 (Exchange Online)"),
    ("spf.messaging.microsoft.com","Microsoft 365"),
    ("_spf.salesforce.com",        "Salesforce"),
    ("_spf.exacttarget.com",       "Salesforce Marketing Cloud"),
    ("_spf.intuit.com",            "Intuit"),
    ("mail.zendesk.com",           "Zendesk"),
    ("_spf.mailgun.org",           "Mailgun"),
    ("mailgun.org",                "Mailgun"),
    ("servers.mcsv.net",           "Mailchimp"),
    ("mcsv.net",                   "Mailchimp"),
    ("mandrillapp.com",            "Mailchimp Transactional (Mandrill)"),
    ("sendgrid.net",               "SendGrid"),
    ("spf.mtasv.net",              "Postmark"),
    ("spf.constantcontact.com",    "Constant Contact"),
    ("_spf.createsend.com",        "Campaign Monitor"),
    ("_spf.smtp2go.com",           "SMTP2GO"),
    ("_spf.brevo.com",             "Brevo (ex-Sendinblue)"),
    ("_spf.sendinblue.com",        "Brevo (ex-Sendinblue)"),
    ("_spf-a.amazonses.com",       "Amazon SES"),
    ("amazonses.com",              "Amazon SES"),
    ("mailjet.com",                "Mailjet"),
    ("_spf.mailbox.org",           "mailbox.org"),
    ("_spf.fastmail.com",          "Fastmail"),
    ("messagingengine.com",        "Fastmail"),
    ("_spf.atlassian.net",         "Atlassian"),
    ("_spf.atlassian.com",         "Atlassian"),
    ("_spf.hubspotemail.net",      "HubSpot"),
    ("hubspot.com",                "HubSpot"),
    ("_spf.zoho.com",              "Zoho Mail"),
    ("_spf.zoho.eu",               "Zoho Mail (EU)"),
    ("_spf.qq.com",                "Tencent QQ Mail"),
    ("_spf.mandrillapp.com",       "Mailchimp Transactional (Mandrill)"),
    ("_spf.proofpoint.com",        "Proofpoint"),
    ("_spf.mimecast.com",          "Mimecast"),
    ("spf.smtp.com",               "SMTP.com"),
    ("_spf.netsuite.com",          "Oracle NetSuite"),
    ("_spf.docusign.net",          "DocuSign"),
    ("_spf.freshdesk.com",         "Freshdesk"),
    ("spf.protonmail.ch",          "Proton Mail"),
    ("_spf.tutanota.de",           "Tuta (ex-Tutanota)"),
    ("_spf.cm.iqemail.com",        "iQ.com (Marketo)"),
    ("_spf.marketo.com",           "Marketo (Adobe)"),
    ("mktomail.com",               "Marketo (Adobe)"),
    ("_spf.icontact.com",          "iContact"),
    ("eo.outboundmail.veritas.com","Veritas / Carbonite"),
)


_SPF_FINAL_RE = re.compile(r"(?:^|\s)([-~?+])all\b", re.IGNORECASE)
_SPF_MECHANISM_RE = re.compile(r"(?:^|\s)([-~?+]?)([a-z][a-z0-9_-]*)(?::([^\s]+))?", re.IGNORECASE)


def _vendor_for_include(target: str) -> str | None:
    """Match an SPF include target against the vendor catalog."""
    needle = target.lower().strip().lstrip(".")
    for suffix, label in _SPF_VENDOR_FINGERPRINTS:
        if needle == suffix or needle.endswith("." + suffix):
            return label
    return None


def _classify_include_targets(targets: list[str]) -> list[str]:
    """Order-preserving dedup of vendor labels for a list of include targets."""
    seen: set[str] = set()
    out: list[str] = []
    for target in targets:
        vendor = _vendor_for_include(target)
        if vendor and vendor not in seen:
            seen.add(vendor)
            out.append(vendor)
    return out


# ---------------------------------------------------------------------------
# MX hostname fingerprinting
# ---------------------------------------------------------------------------


#: MX exchange-hostname suffix → human-readable provider label. Match is
#: case-insensitive and suffix-based (``host == s`` or ``host.endswith("." + s)``)
#: so e.g. ``"mail.protection.outlook.com"`` claims every tenant-named MX
#: shape (``<tenant>.mail.protection.outlook.com``). Sources: the
#: providers' own MX-setup documentation.
_MX_VENDOR_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    # Microsoft 365 hosted Exchange.
    ("mail.protection.outlook.com",  "Microsoft 365 (Exchange Online)"),
    ("mail.eo.outlook.com",          "Microsoft 365 (Exchange Online)"),
    # Google Workspace / Gmail.
    ("aspmx.l.google.com",           "Google Workspace / Gmail"),
    ("googlemail.com",               "Google Workspace / Gmail"),
    # Proton Mail.
    ("protonmail.ch",                "Proton Mail"),
    ("mail.protonmail.ch",           "Proton Mail"),
    ("mailsec.protonmail.ch",        "Proton Mail"),
    # Fastmail (hosts mail under messagingengine.com).
    ("messagingengine.com",          "Fastmail"),
    # Zoho Mail (regional variants).
    ("zoho.com",                     "Zoho Mail"),
    ("zoho.eu",                      "Zoho Mail"),
    ("zohomail.com",                 "Zoho Mail"),
    ("zohomail.eu",                  "Zoho Mail"),
    # mailbox.org.
    ("mailbox.org",                  "mailbox.org"),
    # Cisco IronPort / Email Security Appliance.
    ("iphmx.com",                    "Cisco IronPort / Email Security"),
    # Amazon WorkMail / SES inbound.
    ("awsapps.com",                  "Amazon WorkMail"),
)


def classify_mx_vendor(hostname: str) -> str:
    """Return the human-readable mail provider for an MX exchange hostname.

    Returns the empty string when the hostname does not match any known
    fingerprint. Match is case-insensitive and trailing-dot tolerant.
    """
    if not hostname:
        return ""
    needle = hostname.lower().rstrip(".")
    for suffix, label in _MX_VENDOR_FINGERPRINTS:
        if needle == suffix or needle.endswith("." + suffix):
            return label
    return ""


def parse_spf(domain: str, max_includes: int = 20) -> SPFRecord | None:
    """Look up and parse the SPF record at ``domain``.

    Returns ``None`` if no record exists, or a populated
    :class:`SPFRecord` otherwise. ``include:`` targets are flattened
    one BFS level deep (up to ``max_includes`` total) so the resulting
    ``includes`` list represents the actual sender set, not just the
    surface includes.

    The ``redirect=`` mechanism is recorded but *not* followed for v1
    — operators very rarely use it for sender enumeration; the include
    set is what describes the sender list.
    """
    raw = _fetch_spf(domain)
    if raw is None:
        return None

    record = SPFRecord(raw=raw)
    surface_includes: list[str] = []
    _parse_spf_terms(raw, record, surface_includes_out=surface_includes)

    # BFS flatten: surface include targets first, then one level deeper.
    seen: set[str] = set(surface_includes)
    queue: list[str] = list(surface_includes)
    flattened: list[str] = list(surface_includes)
    budget = max_includes - len(flattened)
    while queue and budget > 0:
        nxt = queue.pop(0)
        sub_raw = _fetch_spf(nxt)
        if sub_raw is None:
            continue
        sub_includes: list[str] = []
        _parse_spf_terms(sub_raw, record=None, surface_includes_out=sub_includes)
        for inc in sub_includes:
            if inc in seen or budget <= 0:
                continue
            seen.add(inc)
            flattened.append(inc)
            queue.append(inc)
            budget -= 1

    record.includes = flattened
    record.sender_vendors = _classify_include_targets(flattened)
    return record


def _fetch_spf(domain: str) -> str | None:
    """Return the raw SPF record at ``domain``, or ``None`` if absent."""
    for record in query_txt(domain):
        if record.lower().startswith("v=spf1"):
            return record
    return None


def _parse_spf_terms(
    raw: str,
    record: SPFRecord | None,
    *,
    surface_includes_out: list[str],
) -> None:
    """Walk SPF terms; populate ``record`` (if given) and collect includes.

    Splitting out the include collection lets the BFS flattener reuse
    the same parser on each child record without rebuilding the full
    :class:`SPFRecord` for every nested lookup.
    """
    final = _SPF_FINAL_RE.search(raw)
    if final and record is not None:
        record.final_qualifier = f"{final.group(1)}all"

    for match in _SPF_MECHANISM_RE.finditer(raw):
        mechanism = match.group(2).lower()
        value = (match.group(3) or "").strip()
        if mechanism == "include" and value:
            surface_includes_out.append(value)
        if record is None:
            continue
        if mechanism == "ip4" and value:
            record.ip4.append(value)
        elif mechanism == "ip6" and value:
            record.ip6.append(value)
        elif mechanism == "a":
            record.a.append(value or "(self)")
        elif mechanism == "mx":
            record.mx.append(value or "(self)")
        elif mechanism == "redirect" and value:
            record.redirect = value


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------


#: rua/ruf hostname suffix → DMARC report-processor vendor.
_DMARC_PROCESSORS: tuple[tuple[str, str], ...] = (
    ("dmarc.postmarkapp.com",   "Postmark (DMARC Digests)"),
    ("dmarcian.com",            "dmarcian"),
    ("dmarcian.eu",             "dmarcian (EU)"),
    ("rua.agari.com",           "Agari (Proofpoint)"),
    ("ruf.agari.com",           "Agari (Proofpoint)"),
    ("reports.proofpoint.com",  "Proofpoint"),
    ("in.valimail.com",         "Valimail"),
    ("valimail.com",            "Valimail"),
    ("mxtoolbox.dmarc-report.com", "MxToolbox"),
    ("dmarc-report.com",        "MxToolbox"),
    ("dmarcadvisor.com",        "DMARC Advisor"),
    ("rep.dmarcanalyzer.com",   "DMARC Analyzer"),
    ("dmarcanalyzer.com",       "DMARC Analyzer"),
    ("urireports.com",          "URIports"),
    ("easydmarc.com",           "EasyDMARC"),
    ("dmarcly.com",             "DMARCLY"),
    ("ondmarc.redsift.com",     "Red Sift OnDMARC"),
    ("redsift.cloud",           "Red Sift"),
    ("250ok.net",               "250ok (Validity)"),
    ("validity.com",            "Validity"),
    ("fraudmarc.com",           "FraudMarc"),
    ("dmarcsmtp.com",           "DMARCsmtp"),
)


def _classify_report_processors(uris: list[str]) -> list[str]:
    """Order-preserving dedup of vendor labels for rua/ruf mailto: URIs."""
    seen: set[str] = set()
    out: list[str] = []
    for uri in uris:
        # Extract host from "mailto:user@host" (and tolerate trailing
        # "!size" report-size qualifiers per RFC 7489 §6.2).
        if "@" not in uri:
            continue
        host = uri.split("@", 1)[1]
        host = host.split("!", 1)[0].strip().lower().rstrip(".")
        for suffix, label in _DMARC_PROCESSORS:
            if host == suffix or host.endswith("." + suffix):
                if label not in seen:
                    seen.add(label)
                    out.append(label)
                break
    return out


def parse_dmarc(domain: str) -> DMARCRecord | None:
    """Look up and parse the DMARC record at ``_dmarc.<domain>``."""
    raw_records = query_txt(f"_dmarc.{domain}")
    raw = next((r for r in raw_records if r.lower().startswith("v=dmarc1")), None)
    if raw is None:
        return None

    record = DMARCRecord(raw=raw)
    for tag in raw.split(";"):
        tag = tag.strip()
        if not tag or "=" not in tag:
            continue
        key, value = tag.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "p":
            record.policy = value.lower()
        elif key == "sp":
            record.subdomain_policy = value.lower()
        elif key == "pct":
            try:
                record.pct = int(value)
            except ValueError:
                pass
        elif key == "rua":
            record.rua = [u.strip() for u in value.split(",") if u.strip()]
        elif key == "ruf":
            record.ruf = [u.strip() for u in value.split(",") if u.strip()]
    record.report_processors = _classify_report_processors(record.rua + record.ruf)
    return record


# ---------------------------------------------------------------------------
# DKIM (selector probe)
# ---------------------------------------------------------------------------


#: Well-known DKIM selectors to probe. Hits document which SaaS-mail
#: providers the domain has set up to sign on its behalf. Absence
#: cannot be claimed — operators choose arbitrary selector names — so
#: the report just lists the selectors that *did* respond.
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "dkim", "dkim1", "mail", "email",
    "google", "google._domainkey",  # legacy aliases
    "selector1", "selector2",       # Microsoft 365
    "s1", "s2",                     # SendGrid
    "k1", "k2", "k3",               # Mailchimp
    "mte1", "mte2",                 # Mimecast
    "mandrill", "mandrill1", "mandrill2",
    "smtp", "smtpapi",
    "fd", "fd2",                    # FastMail
    "mxvault",
    "amazonses", "ses",             # Amazon SES
    "postmark",
    "sparkpost1", "sparkpost2",
    "zoho", "zoho1", "zoho._domainkey",
    "brevo1", "brevo2", "sib1", "sib2",  # Brevo / Sendinblue
    "hubspotemail1", "hubspotemail2",
    "mailo",
    "marketo", "m1._domainkey",
    "freshworks1", "freshworks2",   # Freshworks
    "intuit1", "intuit2",
    "everlytickey1", "everlytickey2",
    "1234567890",  # placeholder no-op (kept for completeness, never matches)
)


def probe_dkim(domain: str, selectors: tuple[str, ...] = DEFAULT_DKIM_SELECTORS) -> list[DKIMSelector]:
    """Probe a list of well-known DKIM selectors at ``domain``.

    Returns only the selectors that *did* return a record. The order of
    the returned list mirrors :data:`DEFAULT_DKIM_SELECTORS` so output
    is stable across runs.
    """
    from concurrent.futures import ThreadPoolExecutor

    def probe_one(selector: str) -> DKIMSelector:
        # Allow selectors that already include ``._domainkey`` so users
        # can pass either form. The double-suffix case is harmless.
        if "._domainkey" in selector:
            qname = f"{selector}.{domain}"
        else:
            qname = f"{selector}._domainkey.{domain}"
        records = query_txt(qname)
        if not records:
            return DKIMSelector(selector=selector, found=False)
        raw = records[0]
        if len(raw) > 200:
            raw = raw[:200] + "…"
        return DKIMSelector(selector=selector, found=True, raw=raw)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(probe_one, selectors))
    return [r for r in results if r.found]


# ---------------------------------------------------------------------------
# BIMI, MTA-STS, TLS-RPT
# ---------------------------------------------------------------------------


def parse_bimi(domain: str) -> BIMIRecord | None:
    """Look up and parse the BIMI record at ``default._bimi.<domain>``."""
    raw_records = query_txt(f"default._bimi.{domain}")
    raw = next((r for r in raw_records if r.lower().startswith("v=bimi1")), None)
    if raw is None:
        return None
    record = BIMIRecord(present=True)
    for tag in raw.split(";"):
        tag = tag.strip()
        if not tag or "=" not in tag:
            continue
        key, value = tag.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "l":
            record.svg_url = value
        elif key == "a":
            record.vmc_url = value
    return record


def parse_mta_sts(domain: str) -> MTASTSStatus | None:
    """Look up the MTA-STS TXT advertisement at ``_mta-sts.<domain>``."""
    raw_records = query_txt(f"_mta-sts.{domain}")
    raw = next((r for r in raw_records if r.lower().startswith("v=stsv1")), None)
    if raw is None:
        return None
    sts_id = ""
    for tag in raw.split(";"):
        tag = tag.strip()
        if tag.lower().startswith("id="):
            sts_id = tag.split("=", 1)[1].strip()
    return MTASTSStatus(txt_present=True, txt_id=sts_id)


def parse_tls_rpt(domain: str) -> TLSRPTStatus | None:
    """Look up the TLS-RPT TXT at ``_smtp._tls.<domain>``."""
    raw_records = query_txt(f"_smtp._tls.{domain}")
    raw = next((r for r in raw_records if r.lower().startswith("v=tlsrptv1")), None)
    if raw is None:
        return None
    status = TLSRPTStatus(txt_present=True)
    for tag in raw.split(";"):
        tag = tag.strip()
        if tag.lower().startswith("rua="):
            value = tag.split("=", 1)[1].strip()
            status.rua = [v.strip() for v in value.split(",") if v.strip()]
    return status


__all__ = [
    "DEFAULT_DKIM_SELECTORS",
    "parse_bimi",
    "parse_dmarc",
    "parse_mta_sts",
    "parse_spf",
    "parse_tls_rpt",
    "probe_dkim",
]
