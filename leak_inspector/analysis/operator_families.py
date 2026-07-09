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

"""Curated operator-domain families for first-party classification.

Large operators run their products from many registrable domains
(Microsoft serves microsoft.com itself, but also fetches assets from
``s-microsoft.com``, signs users in via ``microsoftonline.com`` and
``live.com``, embeds Dynamics widgets from ``dynamics.com``, fronts
traffic through ``azurefd.net``, …). A plain eTLD+1 comparison against
the bundle's ``base_domain`` flags every one of those as third-party,
which is technically true at the DNS level but wrong for sovereignty
purposes: it's all the same legal entity, the same CLOUD-Act exposure,
the same data-protection-authority responsibility.

This module fixes that by mapping each known operator's domain set
into a family. :func:`same_operator` returns ``True`` if two domains
are either equal or members of the same family, so the report
collapses Microsoft-on-Microsoft (Google-on-Google, …) traffic back
into the first-party footprint.

The map is intentionally **conservative**:

* Only the operator's own infrastructure / asset / auth / app-delivery
  domains are listed — the things that exist *to serve the operator's
  own product family*.
* Brand-distinct subsidiaries that operate as their own products
  (LinkedIn, GitHub, Skype, Instagram, WhatsApp, …) are deliberately
  **excluded**. They share the parent's CLOUD-Act exposure, but a
  publisher embedding e.g. a LinkedIn share button on microsoft.com is
  a separate data flow worth surfacing as third-party in the report.

Adding new entries: include only domains the operator publicly
acknowledges owning AND that serve the operator's own product family
rather than a brand-distinct subsidiary product.
"""

from __future__ import annotations


#: ``operator_label`` → frozenset of eTLD+1s the operator runs as part
#: of its own product family.
FAMILIES: dict[str, frozenset[str]] = {
    "Microsoft": frozenset({
        "microsoft.com",
        "microsoft.net",
        "s-microsoft.com",
        "microsoftonline.com",
        "microsoftonline-p.com",
        "live.com",
        "live.net",
        "msn.com",
        "office.com",
        "office.net",
        "office365.com",
        "outlook.com",
        "onedrive.com",
        "msocdn.com",
        "sharepoint.com",
        "sharepointonline.com",
        "bing.com",
        "bingapis.com",
        "windows.com",
        "windows.net",
        "windowsupdate.com",
        "windowsazure.com",
        "azure.com",
        "azureedge.net",
        "azurewebsites.net",
        "azurefd.net",
        "dynamics.com",
        "signalr.net",
        "msftauth.net",
        "msecnd.net",
        "aspnetcdn.com",
        "aka.ms",
        "visualstudio.com",
        "vsassets.io",
        "xboxlive.com",
    }),
    "Google": frozenset({
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "googletagmanager.com",
        "googlesyndication.com",
        "googleadservices.com",
        "google-analytics.com",
        "doubleclick.net",
        "youtube.com",
        "youtu.be",
        "ytimg.com",
        "googlevideo.com",
        "googlemail.com",
        "ggpht.com",
        "gvt1.com",
        "gvt2.com",
        "ampproject.org",
        "withgoogle.com",
        "chrome.com",
        "chromium.org",
        "app-measurement.com",
        "appspot.com",
        "blogger.com",
        "blogspot.com",
        "gmail.com",
        # Google operates several brand domains on its own ``.google`` TLD;
        # tldextract treats ``blog.google`` (etc.) as its own eTLD+1.
        "blog.google",
        "domains.google",
        "cloud.google",
    }),
    "Adobe": frozenset({
        "adobe.com",
        "adobedtm.com",
        "omtrdc.net",
        "demdex.net",
        "2o7.net",
        "everesttech.net",
        "typekit.net",
        "adobedc.net",
        "tubemogul.com",
        "marketo.com",
        "mktomail.com",
        "mktoresp.com",
        "adobelogin.com",
        "behance.net",
    }),
    "Meta": frozenset({
        "facebook.com",
        "meta.com",
        "fbcdn.net",
        "fbsbx.com",
        "fb.com",
        "fb.me",
    }),
    "Apple": frozenset({
        "apple.com",
        "icloud.com",
        "cdn-apple.com",
        "mzstatic.com",
        "apple-mapkit.com",
        "applemusic.com",
    }),
    "Amazon": frozenset({
        "amazon.com",
        "awsstatic.com",
        "cloudfront.net",
        "amazonaws.com",
        "media-amazon.com",
        "images-amazon.com",
        "ssl-images-amazon.com",
        "amazontrust.com",
        "amazonpay.com",
    }),
    "Yahoo": frozenset({
        "yahoo.com",
        "yimg.com",
        "yahooinc.com",
    }),
}


#: Reverse index built once at import time. eTLD+1 → operator label.
_DOMAIN_TO_OPERATOR: dict[str, str] = {
    domain: operator
    for operator, domains in FAMILIES.items()
    for domain in domains
}


def operator_label(registrable_domain: str) -> str:
    """Return the operator-family name for ``registrable_domain``, or ``""``.

    ``registrable_domain`` is an eTLD+1 string (e.g. ``"s-microsoft.com"``).
    Comparison is case-insensitive.
    """
    if not registrable_domain:
        return ""
    return _DOMAIN_TO_OPERATOR.get(registrable_domain.lower(), "")


def same_operator(domain_a: str, domain_b: str) -> bool:
    """Return ``True`` if two eTLD+1s belong to the same operator family.

    Equality counts as same-operator. Empty inputs return ``False`` so
    the function is safe to call against captures where a manifest's
    ``base_domain`` could not be determined.
    """
    if not domain_a or not domain_b:
        return False
    a = domain_a.lower()
    b = domain_b.lower()
    if a == b:
        return True
    operator_a = _DOMAIN_TO_OPERATOR.get(a)
    operator_b = _DOMAIN_TO_OPERATOR.get(b)
    return operator_a is not None and operator_a == operator_b


__all__ = [
    "FAMILIES",
    "operator_label",
    "same_operator",
]