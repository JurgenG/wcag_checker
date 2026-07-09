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

"""Productivity-suite OSINT probes (Microsoft 365 + Google Workspace).

Each probe queries a fixed set of subdomains of the target domain and
inspects the CNAME / TXT response for the vendor's published patterns:

* **Microsoft 365** publishes a well-known set of CNAME targets that
  customers point their subdomains at to enable mail client
  auto-discovery, Teams, Skype-for-Business SIP federation, Entra ID
  (Azure AD) join, Intune MDM enrollment, and Exchange DKIM. The CNAME
  target shapes are documented in the M365 admin guide and don't vary
  per tenant (except DKIM, where the target reveals the tenant name).

* **Google Workspace** publishes branded URL CNAMEs (mail/calendar/
  drive/docs/sites → ``ghs.googlehosted.com``) plus the
  ``google._domainkey`` DKIM TXT record (``v=DKIM1`` selector at that
  fixed name).

These are pure OSINT — no authentication needed, no rate-limited APIs.
Each probe is one DNS query, so the whole sweep is ~12 lookups per
domain and is run inside the existing orchestrator thread pool.
"""

from __future__ import annotations

from dataclasses import dataclass

from .resolvers import query_cname, query_txt


@dataclass(frozen=True)
class ProductivityProbe:
    """A single confirmed productivity-suite signal for a domain.

    ``label`` is a human-readable summary (vendor + signal description).
    ``signal_type`` is one of ``"cname"`` (M365/Workspace branded CNAME),
    ``"dkim_cname"`` (M365 DKIM selector exposing tenant name), or
    ``"dkim_txt"`` (Google Workspace DKIM TXT). ``subdomain`` is the
    fully-qualified name that was probed; ``target`` is what the
    resolver returned (CNAME target or truncated TXT value).
    """

    label: str
    vendor: str
    signal_type: str
    subdomain: str
    target: str


# --- Microsoft 365 ----------------------------------------------------------


#: M365 standard CNAME probes. Each entry is
#: ``(subname, expected_target_substring, label_description)``. The
#: expected target is matched as ``in`` (substring) against the CNAME
#: target so trailing dots / case differences don't matter.
_M365_CNAME_PROBES: tuple[tuple[str, str, str], ...] = (
    ("autodiscover",
     "outlook.com",
     "Outlook autodiscover (mail client config)"),
    ("lyncdiscover",
     "online.lync.com",
     "Teams / Skype-for-Business presence"),
    ("sip",
     "online.lync.com",
     "Teams calling — SIP federation"),
    ("enterpriseregistration",
     "enterpriseregistration.windows.net",
     "Entra ID (Azure AD) device join"),
    ("enterpriseenrollment",
     "enterpriseenrollment.manage.microsoft.com",
     "Intune MDM device enrollment"),
)

#: DKIM selectors that, when CNAMEd, reveal the M365 tenant name (the
#: ``<tenant>.onmicrosoft.com`` slug). Match accepts any target that
#: starts with ``selector{N}-`` AND ends in ``.onmicrosoft.com`` so the
#: tenant name is observable in :attr:`ProductivityProbe.target`.
_M365_DKIM_SELECTORS: tuple[tuple[str, str], ...] = (
    ("selector1._domainkey", "selector1-"),
    ("selector2._domainkey", "selector2-"),
)


def probe_m365(domain: str) -> list[ProductivityProbe]:
    """Run the Microsoft 365 OSINT probe suite against ``domain``."""
    probes: list[ProductivityProbe] = []
    for subname, expected, description in _M365_CNAME_PROBES:
        fqdn = f"{subname}.{domain}"
        for target in query_cname(fqdn):
            target_lower = target.lower().rstrip(".")
            if expected in target_lower:
                probes.append(ProductivityProbe(
                    label=f"Microsoft 365 — {description}",
                    vendor="Microsoft 365",
                    signal_type="cname",
                    subdomain=fqdn,
                    target=target_lower,
                ))
                break  # one match per subname is enough
    for subname, target_prefix in _M365_DKIM_SELECTORS:
        fqdn = f"{subname}.{domain}"
        for target in query_cname(fqdn):
            target_lower = target.lower().rstrip(".")
            if (
                target_lower.startswith(target_prefix)
                and ".onmicrosoft.com" in target_lower
            ):
                selector_name = subname.split(".")[0]
                probes.append(ProductivityProbe(
                    label=f"Microsoft 365 — Exchange DKIM ({selector_name})",
                    vendor="Microsoft 365",
                    signal_type="dkim_cname",
                    subdomain=fqdn,
                    target=target_lower,
                ))
                break
    return probes


# --- Google Workspace ------------------------------------------------------


#: Workspace branded-URL CNAMEs. All point to the same Google host;
#: subname presence is the meaningful signal.
_WORKSPACE_CNAME_SUBNAMES: tuple[tuple[str, str], ...] = (
    ("mail",     "Branded Gmail web URL"),
    ("calendar", "Branded Google Calendar URL"),
    ("drive",    "Branded Google Drive URL"),
    ("docs",     "Branded Google Docs URL"),
    ("sites",    "Branded Google Sites URL"),
)
_WORKSPACE_CNAME_TARGET = "ghs.googlehosted.com"

#: Workspace DKIM selector — TXT record (NOT a CNAME, unlike M365).
_WORKSPACE_DKIM_SUBNAME = "google._domainkey"


def probe_workspace(domain: str) -> list[ProductivityProbe]:
    """Run the Google Workspace OSINT probe suite against ``domain``."""
    probes: list[ProductivityProbe] = []
    for subname, description in _WORKSPACE_CNAME_SUBNAMES:
        fqdn = f"{subname}.{domain}"
        for target in query_cname(fqdn):
            target_lower = target.lower().rstrip(".")
            if _WORKSPACE_CNAME_TARGET in target_lower:
                probes.append(ProductivityProbe(
                    label=f"Google Workspace — {description}",
                    vendor="Google Workspace",
                    signal_type="cname",
                    subdomain=fqdn,
                    target=target_lower,
                ))
                break
    dkim_fqdn = f"{_WORKSPACE_DKIM_SUBNAME}.{domain}"
    for record in query_txt(dkim_fqdn):
        if "v=DKIM1" in record:
            preview = record if len(record) <= 80 else record[:77] + "…"
            probes.append(ProductivityProbe(
                label="Google Workspace — Gmail DKIM",
                vendor="Google Workspace",
                signal_type="dkim_txt",
                subdomain=dkim_fqdn,
                target=preview,
            ))
            break
    return probes


def probe_all(domain: str) -> list[ProductivityProbe]:
    """Run every productivity-suite probe against ``domain``.

    Returns the concatenated list of probe hits across all vendors. The
    caller can group by :attr:`ProductivityProbe.vendor` if it wants
    per-vendor display.
    """
    return probe_m365(domain) + probe_workspace(domain)


__all__ = [
    "ProductivityProbe",
    "probe_all",
    "probe_m365",
    "probe_workspace",
]
