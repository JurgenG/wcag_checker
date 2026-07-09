"""CNAME-tail → CDN / edge-provider / vendor-own-infra classifier.

Pure data lookup. Given the CNAME chain captured for a host, returns
the provider that operates the tail of the chain (or ``None`` when
the tail is unknown — we refuse to guess).

Surfacing this in the report tells an auditor *where the traffic
actually terminates*, not just where the URL appears to point. A
``vlaanderen.be`` subdomain that CNAMEs to ``akamaiedge.net`` is
operated by Akamai (US jurisdiction); a ``www.example.be`` that
CNAMEs to ``cloudflare.net`` is fronted by Cloudflare. The visible
URL alone hides that.

Each entry in :data:`_PROVIDERS` is justified by a real CNAME chain
observed in the test fixture bundles. Adding a new entry requires
the same justification — no speculation per CLAUDE.md.

Categories:

* ``"cdn"`` — pure edge / content-delivery network (Akamai,
  Cloudflare, Fastly, Azure Front Door, AWS CloudFront).
* ``"cloud"`` — general-purpose cloud whose CNAME tail indicates the
  region or service (raw ``amazonaws.com`` regional endpoints).
* ``"vendor_own"`` — the vendor's own infrastructure (Hotjar on
  ``hotjar.com``, Meta on ``fbcdn.net``). The traffic still
  terminates at the vendor; the CNAME just reveals which physical
  hosting they chose.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ProviderInfo:
    """One CDN / edge / vendor-own provider identified from a CNAME tail."""

    name: str               # human-readable label
    category: str           # "cdn" | "cloud" | "vendor_own"
    jurisdiction: str       # ISO 3166-1 alpha-2 (typically the company's home)


#: Tail-suffix → ProviderInfo. The lookup is "any chain whose tail
#: ENDS with this suffix at a registrable-domain boundary". Order in
#: this dict does not matter; ``cname_provider_from_chain`` picks the
#: longest matching suffix so e.g. ``"l.google.com"`` wins over a
#: hypothetical bare ``"google.com"`` entry.
_PROVIDERS: dict[str, ProviderInfo] = {
    # --- Pure CDN / edge ---------------------------------------------------
    "akamaiedge.net":         ProviderInfo("Akamai",           "cdn",   "US"),
    "edgekey.net":            ProviderInfo("Akamai",           "cdn",   "US"),
    "edgesuite.net":          ProviderInfo("Akamai",           "cdn",   "US"),
    "akamaihd.net":           ProviderInfo("Akamai",           "cdn",   "US"),
    "cloudflare.net":         ProviderInfo("Cloudflare",       "cdn",   "US"),
    "cloudflare.com":         ProviderInfo("Cloudflare",       "cdn",   "US"),
    "cdn.cloudflare.net":     ProviderInfo("Cloudflare",       "cdn",   "US"),
    "fastly.net":             ProviderInfo("Fastly",           "cdn",   "US"),
    "fastlylb.net":           ProviderInfo("Fastly",           "cdn",   "US"),
    "cloudfront.net":         ProviderInfo("AWS CloudFront",   "cdn",   "US"),
    "tm-azurefd.net":         ProviderInfo("Azure Front Door", "cdn",   "US"),
    "azurefd.net":            ProviderInfo("Azure Front Door", "cdn",   "US"),
    "azureedge.net":          ProviderInfo("Azure CDN",        "cdn",   "US"),

    # --- Cloud raw endpoints ----------------------------------------------
    # ``*.amazonaws.com`` is normally not a chain tail (real production
    # traffic CNAMEs through a CDN first), but a few bundles show direct
    # AWS endpoints — keep this entry honest.
    "amazonaws.com":          ProviderInfo("AWS",              "cloud", "US"),

    # --- Vendor-own infrastructure (the chain reveals the host, not a
    #     third party). Useful because the auditor sees, e.g., that
    #     Hotjar runs on AWS EKS — but the data still goes to Hotjar.
    "hotjar.com":             ProviderInfo("Hotjar",           "vendor_own", "US"),
    "hotjar.io":              ProviderInfo("Hotjar",           "vendor_own", "US"),
    "l.google.com":           ProviderInfo("Google",           "vendor_own", "US"),
    "googleusercontent.com":  ProviderInfo("Google",           "vendor_own", "US"),
    "fbcdn.net":              ProviderInfo("Meta",             "vendor_own", "US"),
    "facebook.com":           ProviderInfo("Meta",             "vendor_own", "US"),
    "adnxs.com":              ProviderInfo("Xandr (Microsoft)", "vendor_own", "US"),
    "omtrdc.net":             ProviderInfo("Adobe",            "vendor_own", "US"),
    "demdex.net":             ProviderInfo("Adobe",            "vendor_own", "US"),
}


def cname_provider_from_chain(chain: Optional[list[str]]) -> Optional[ProviderInfo]:
    """Return the provider that operates the tail of ``chain``, or ``None``.

    ``chain`` is the per-host CNAME chain as captured into the bundle:
    a list ``[host, alias_1, alias_2, ..., final_canonical]``. A chain
    that's just ``[host]`` (no real CNAME hop) returns ``None``.

    The matching rule is "longest registrable-domain suffix wins" —
    so ``"youtube-ui.l.google.com"`` matches the ``"l.google.com"``
    entry, not a hypothetical bare ``"google.com"``.
    """
    if not chain or len(chain) < 2:
        return None
    tail = (chain[-1] or "").lower().rstrip(".")
    if not tail:
        return None
    # Longest-suffix match — sort keys by length descending so a more
    # specific tail key (``"cdn.cloudflare.net"``) beats a less
    # specific one (``"cloudflare.net"``).
    for key in sorted(_PROVIDERS, key=len, reverse=True):
        if _tail_matches(tail, key):
            return _PROVIDERS[key]
    return None


def _tail_matches(tail: str, key: str) -> bool:
    """``tail`` ends with ``key`` at a domain-label boundary.

    ``"foo.example.com"`` matches ``"example.com"``; ``"fooexample.com"``
    does not. Both inputs are lowercased before comparison.
    """
    key = key.lower().rstrip(".")
    if tail == key:
        return True
    return tail.endswith("." + key)


__all__ = ["ProviderInfo", "cname_provider_from_chain"]
