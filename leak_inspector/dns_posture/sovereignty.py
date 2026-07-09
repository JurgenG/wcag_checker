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

"""ASN / geo enrichment + TXT-verification fingerprints + NS provider.

The classifications here translate raw DNS data into sovereignty-
relevant labels:

* :func:`enrich_ip` adds ASN (Team Cymru) and country (MaxMind) to a
  bare IP string.
* :func:`detect_verification` matches a TXT record against a curated
  catalog of well-known SaaS verification tokens (Google / M365 / Meta
  / Apple / GitHub / Atlassian / Adobe / Stripe / SES / Docusign /
  Zoom / Cisco / …). Each hit is a self-disclosed third-party data
  flow.
* :func:`asn_to_provider` collapses raw AS-org strings into a clean
  provider label for NS attribution.
"""

from __future__ import annotations

import re

from .geoip import CountryReader
from .resolvers import query_a, query_aaaa, reverse_via_cymru
from .types import IPInfo, TXTVerification


# ---------------------------------------------------------------------------
# IP enrichment
# ---------------------------------------------------------------------------


def enrich_ip(
    address: str, version: int, geo_reader: CountryReader | None
) -> IPInfo:
    """Build an :class:`IPInfo` from an IP string + version.

    ASN comes from Team Cymru (always attempted), country comes from the
    MaxMind reader (only when one is provided). Either side missing is
    fine — both fields just stay empty.
    """
    asn, org, cymru_country = reverse_via_cymru(address)
    iso, name = ("", "")
    if geo_reader is not None:
        iso, name = geo_reader.country(address)
    if not iso and cymru_country:
        iso = cymru_country  # Team Cymru fallback when no mmdb available
    return IPInfo(
        address=address,
        version=version,
        asn=asn,
        as_org=org,
        country_code=iso,
        country_name=name,
        asn_country=cymru_country,
    )


def enrich_host(host: str, geo_reader: CountryReader | None = None) -> IPInfo | None:
    """Resolve ``host`` to its first A/AAAA record and enrich the IP.

    Returns ``None`` when no addresses resolve. Prefers IPv4 (more
    ASN-lookup coverage via Team Cymru); falls back to IPv6 only if no
    A records exist. Empty enrichment fields are kept — the caller
    decides how to render partial data.
    """
    addresses = query_a(host)
    version = 4
    if not addresses:
        addresses = query_aaaa(host)
        version = 6
    if not addresses:
        return None
    return enrich_ip(addresses[0], version, geo_reader)


# ---------------------------------------------------------------------------
# NS / hosting provider attribution
# ---------------------------------------------------------------------------


#: AS-organisation substrings → friendly provider label. Matched
#: case-insensitively. First hit wins, ordered most-specific first.
_PROVIDER_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("CLOUDFLARE",            "Cloudflare"),
    ("AMAZON-",               "Amazon Web Services"),
    ("AMAZON.COM",            "Amazon Web Services"),
    ("AMAZON",                "Amazon"),
    ("GOOGLE-CLOUD-PLATFORM", "Google Cloud"),
    ("GOOGLE LLC",            "Google"),
    ("GOOGLE",                "Google"),
    ("MICROSOFT-CORP",        "Microsoft Azure"),
    ("MICROSOFT",             "Microsoft"),
    ("AKAMAI",                "Akamai"),
    ("FASTLY",                "Fastly"),
    ("DIGITALOCEAN",          "DigitalOcean"),
    ("LINODE",                "Linode / Akamai"),
    ("HETZNER",               "Hetzner Online"),
    ("OVH",                   "OVHcloud"),
    ("SCALEWAY",              "Scaleway"),
    ("LEASEWEB",              "Leaseweb"),
    ("HURRICANE",             "Hurricane Electric"),
    ("GITHUB",                "GitHub"),
    ("VERCEL",                "Vercel"),
    ("NETLIFY",               "Netlify"),
    ("HEROKU",                "Heroku"),
    ("ORACLE",                "Oracle Cloud"),
    ("ALIBABA",               "Alibaba Cloud"),
    ("TENCENT",               "Tencent Cloud"),
    ("BAIDU",                 "Baidu"),
    ("YANDEX",                "Yandex"),
)


def asn_to_provider(as_org: str) -> str:
    """Collapse an AS-org string to a friendly provider label.

    Returns the original ``as_org`` if no fingerprint matches — better
    to expose the raw AS-org than to guess.
    """
    if not as_org:
        return ""
    upper = as_org.upper()
    for needle, label in _PROVIDER_FINGERPRINTS:
        if needle in upper:
            return label
    return as_org


# ---------------------------------------------------------------------------
# TXT verification fingerprints
# ---------------------------------------------------------------------------


#: Catalog of well-known TXT-verification token prefixes / patterns.
#: Each entry classifies one TXT-record fingerprint into a vendor +
#: jurisdiction so the report can list which SaaS the domain has
#: self-attested to using.
#:
#: Match modes:
#:   * ``"prefix"`` — case-insensitive ``startswith()``.
#:   * ``"contains"`` — case-insensitive substring (use sparingly to
#:     avoid false positives).
#:   * ``"regex"``    — anchored regex against the record.
#:
#: Sources are the vendors' own setup instructions (Google Admin
#: console, Microsoft 365 admin centre, Meta Business Suite, etc.).
_VERIFICATION_FINGERPRINTS: tuple[tuple[str, str, str, str, str], ...] = (
    # (match_mode, pattern, vendor, purpose, jurisdiction)
    ("prefix",  "google-site-verification=",        "Google",            "Workspace / Search Console",     "US"),
    ("prefix",  "google-gws-recovery-domain-verification=", "Google",    "Workspace recovery",             "US"),
    ("regex",   r"^MS=[A-Z0-9]+$",                  "Microsoft 365",     "Office 365 tenant verification", "US"),
    ("regex",   r"^MSn=[A-Z0-9]+$",                 "Microsoft 365",     "Office 365 nonce verification",  "US"),
    ("prefix",  "facebook-domain-verification=",    "Meta",              "Business / Pixel verification",  "US"),
    ("prefix",  "apple-domain-verification=",       "Apple",             "Apple services domain verification","US"),
    ("prefix",  "atlassian-domain-verification=",   "Atlassian",         "Atlassian Cloud verification",   "AU"),
    ("prefix",  "adobe-idp-site-verification=",     "Adobe",             "IdP / Creative Cloud verification","US"),
    ("prefix",  "adobe-sign-verification=",         "Adobe",             "Adobe Sign verification",        "US"),
    ("prefix",  "stripe-verification=",             "Stripe",            "Stripe domain verification",     "US"),
    ("prefix",  "_amazonses=",                      "Amazon SES",        "SES sender verification",        "US"),
    ("prefix",  "amazonses:",                       "Amazon SES",        "SES sender verification",        "US"),
    ("prefix",  "_github-challenge-",               "GitHub",            "GitHub domain verification",     "US"),
    ("prefix",  "docusign=",                        "DocuSign",          "DocuSign domain verification",   "US"),
    ("prefix",  "zoom_verify_",                     "Zoom",              "Zoom domain verification",       "US"),
    ("prefix",  "cisco-ci-domain-verification=",    "Cisco",             "Webex / Cisco verification",     "US"),
    ("prefix",  "intercom-domain-verification=",    "Intercom",          "Intercom domain verification",   "US"),
    ("prefix",  "hubspot-verification=",            "HubSpot",           "HubSpot domain verification",    "US"),
    ("prefix",  "mailru-verification:",             "Mail.ru",           "Mail.ru domain verification",    "RU"),
    ("prefix",  "yandex-verification:",             "Yandex",            "Yandex domain verification",     "RU"),
    ("prefix",  "baidu-site-verification=",         "Baidu",             "Baidu domain verification",      "CN"),
    ("prefix",  "have-i-been-pwned-verification=",  "Have I Been Pwned", "HIBP domain verification",       "AU"),
    ("prefix",  "miro-verification=",               "Miro",              "Miro domain verification",      "US"),
    ("prefix",  "logmein-verification-code=",       "LogMeIn",           "LogMeIn / GoTo verification",    "US"),
    ("prefix",  "loaderio=",                        "Loader.io (SendGrid)", "Load-testing verification",  "US"),
    ("prefix",  "pinterest-site-verification=",     "Pinterest",         "Pinterest domain verification",  "US"),
    ("prefix",  "globalsign-domain-verification=",  "GlobalSign",        "GlobalSign domain verification", "BE"),
    ("prefix",  "ahrefs-site-verification_",        "Ahrefs",            "Ahrefs SEO verification",        "SG"),
    ("prefix",  "asv=",                             "Atlassian",         "Atlassian Statuspage verification","AU"),
    ("prefix",  "wormly=",                          "Wormly",            "Wormly uptime verification",     "AU"),
    ("prefix",  "openai-domain-verification=",      "OpenAI",            "OpenAI domain verification",     "US"),
    ("prefix",  "anthropic-domain-verification=",   "Anthropic",         "Anthropic domain verification",  "US"),
    ("prefix",  "slack-domain-verification=",       "Slack (Salesforce)","Slack domain verification",      "US"),
    ("prefix",  "dropbox-domain-verification=",     "Dropbox",           "Dropbox domain verification",    "US"),
    ("prefix",  "notion-domain-verification=",      "Notion",            "Notion domain verification",     "US"),
    ("prefix",  "asana-domain-verification=",       "Asana",             "Asana domain verification",      "US"),
    ("prefix",  "atlassian-sending-domain-verification=", "Atlassian",   "Atlassian Cloud verification",   "AU"),
)

_PRECOMPILED_REGEX: dict[str, re.Pattern] = {}


def detect_verification(record: str) -> TXTVerification | None:
    """Classify one TXT record against the verification-fingerprint catalog.

    Returns ``None`` if the record doesn't match any known vendor
    fingerprint. The matcher is conservative: prefix and substring
    matches are case-insensitive but anchored, so unrelated TXT
    records (SPF, DMARC, custom verifications) don't trigger false
    positives.
    """
    if not record:
        return None
    stripped = record.strip()
    if not stripped:
        return None
    upper = stripped.upper()
    for mode, pattern, vendor, purpose, jurisdiction in _VERIFICATION_FINGERPRINTS:
        if mode == "prefix":
            if upper.startswith(pattern.upper()):
                return TXTVerification(
                    vendor=vendor, purpose=purpose, jurisdiction=jurisdiction
                )
        elif mode == "contains":
            if pattern.upper() in upper:
                return TXTVerification(
                    vendor=vendor, purpose=purpose, jurisdiction=jurisdiction
                )
        elif mode == "regex":
            regex = _PRECOMPILED_REGEX.get(pattern)
            if regex is None:
                regex = re.compile(pattern, re.IGNORECASE)
                _PRECOMPILED_REGEX[pattern] = regex
            if regex.search(stripped):
                return TXTVerification(
                    vendor=vendor, purpose=purpose, jurisdiction=jurisdiction
                )
    return None


__all__ = [
    "asn_to_provider",
    "detect_verification",
    "enrich_host",
    "enrich_ip",
]
