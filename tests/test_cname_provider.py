"""Tests for the CNAME-tail → CDN/edge-provider classifier.

Pure data: given a CNAME chain (as captured into the bundle), return
the provider that operates the chain's tail. Curated flat dict —
each entry is justified by a real chain observed in at least one of
the test fixture bundles.
"""

from __future__ import annotations

from leak_inspector.cname_provider import (
    ProviderInfo,
    cname_provider_from_chain,
)


# --- Real-chain matches, one per provider seed ----------------------------


def test_akamai_via_akamaiedge_tail() -> None:
    """Brecht: prod.widgets.burgerprofiel.vlaanderen.be →
    aiv.edgekey.net → e10001669.dscb.akamaiedge.net."""
    chain = [
        "prod.widgets.burgerprofiel.vlaanderen.be",
        "aiv.edgekey.net",
        "e10001669.dscb.akamaiedge.net",
    ]
    p = cname_provider_from_chain(chain)
    assert p is not None
    assert p.name == "Akamai"
    assert p.jurisdiction == "US"


def test_azure_front_door_via_tm_azurefd_tail() -> None:
    """Brecht: rumst-p2-brecht.azureedge.net → ... → tm-azurefd.net."""
    chain = [
        "rumst-p2-brecht.azureedge.net",
        "rumst-p2-brecht.afd.azureedge.net",
        "reserved-g01.afd.azureedge.net",
        "mr-afd-azuredge-reserved-g01.tm-azurefd.net",
    ]
    p = cname_provider_from_chain(chain)
    assert p is not None
    assert "Azure" in p.name
    assert p.jurisdiction == "US"


def test_cloudflare_via_cloudflare_net_tail() -> None:
    """NBB: www.nbb.be → www.nbb.be.cdn.cloudflare.net."""
    chain = ["www.nbb.be", "www.nbb.be.cdn.cloudflare.net"]
    p = cname_provider_from_chain(chain)
    assert p is not None
    assert p.name == "Cloudflare"
    assert p.jurisdiction == "US"


def test_google_via_l_google_com_tail() -> None:
    """cultuurkuur: www.youtube.com → youtube-ui.l.google.com."""
    chain = ["www.youtube.com", "youtube-ui.l.google.com"]
    p = cname_provider_from_chain(chain)
    assert p is not None
    assert p.name == "Google"
    assert p.jurisdiction == "US"


def test_meta_cdn_via_fbcdn_tail() -> None:
    """aalst: connect.facebook.net → scontent.xx.fbcdn.net."""
    chain = ["connect.facebook.net", "scontent.xx.fbcdn.net"]
    p = cname_provider_from_chain(chain)
    assert p is not None
    assert "Meta" in p.name or "Facebook" in p.name
    assert p.jurisdiction == "US"


def test_hotjar_self_via_hotjar_com_tail() -> None:
    """cultuurkuur: metrics.hotjar.io → pacman-metrics-live.live.eks.hotjar.com."""
    chain = [
        "metrics.hotjar.io",
        "pacman-metrics-live.live.eks.hotjar.com",
    ]
    p = cname_provider_from_chain(chain)
    assert p is not None
    assert p.name == "Hotjar"
    # Vendor's own infrastructure — but running on AWS EKS, US-juris.
    assert p.jurisdiction == "US"


# --- Negative cases -------------------------------------------------------


def test_no_cname_hop_returns_none() -> None:
    """A chain that's just the host repeating itself has no CNAME tail."""
    assert cname_provider_from_chain(["www.example.be"]) is None


def test_empty_chain_returns_none() -> None:
    assert cname_provider_from_chain([]) is None


def test_unknown_tail_returns_none() -> None:
    """A tail we haven't seeded returns None rather than guessing."""
    chain = ["alias.example.com", "tail.unknown-provider.example"]
    assert cname_provider_from_chain(chain) is None


def test_none_chain_returns_none() -> None:
    """Defensive: ``None`` instead of a list is treated as 'no chain'."""
    assert cname_provider_from_chain(None) is None


# --- ProviderInfo contract ------------------------------------------------


def test_provider_info_category_uses_canonical_strings() -> None:
    """Categories constrain the report's framing — keep the vocabulary small."""
    p = cname_provider_from_chain(["x.example", "tail.akamaiedge.net"])
    assert p.category in {"cdn", "cloud", "vendor_own"}
