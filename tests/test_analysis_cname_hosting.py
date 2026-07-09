"""Public-sector hosting CNAMEs are not tracker cloaking.

Many Walloon municipalities host their whole site on IMIO (a public
intercommunal): ``www.<commune>.be`` → ``…imio.be``. The generic
CNAME-cloak detector matched that chain and stamped a
``(cname-cloak)`` marker, which the privacy score reads as a
first-party-evasion *tracker* (−2 evasion + counted as a third-party
controller). That is wrong: IMIO is the site's own host, a
``para_government`` module — the opposite of a tracker hiding behind
first-party DNS.

The fix: the CNAME-cloak marker is only stamped for
``MODULE_KIND_TRACKER`` modules. A government / para-government module
matched via CNAME is still *attributed* (so the report can say "hosted
by IMIO"), but carries no cloak marker, so scoring treats those hits
as the first-party page resources they are.
"""

from __future__ import annotations

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent


def _manifest(base: str = "ciney.be") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-06-07T00:00:00Z",
        ended_at="2026-06-07T00:01:00Z",
        target_url=f"https://www.{base}/", base_domain=base,
        browser={}, profile="p", landing_url=f"https://www.{base}/",
    )


def _request(host: str, path: str = "/", query: str = "") -> RequestEvent:
    url = f"https://{host}{path}" + (f"?{query}" if query else "")
    return RequestEvent(
        event_id=1, timestamp="2026-06-07T00:00:10Z", type="request",
        context_id="ctx-top", payload={}, method="GET", url=url, host=host,
        headers={}, request_body=None, initiator=None,
        response_status=200, response_mime="text/html", response_headers={},
    )


# www.ciney.be -> site-ciney.imio.be -> cf.imio.be (real chain shape).
_IMIO_CHAIN = {
    "www.ciney.be": ["www.ciney.be", "site-ciney.imio.be", "cf.imio.be"],
}


def test_imio_hosting_is_attributed_but_not_cloak_marked() -> None:
    event = _request("www.ciney.be", path="/home")
    analysis = analyze_events(
        _manifest(), [event], cname_chains=_IMIO_CHAIN,
    )
    imio = [h for h in analysis.hits if h.module_id == "paragov_imio"]
    assert imio, "IMIO host should still be recognised via the CNAME chain"
    # ...but NOT as a first-party-evasion cloak.
    assert not any(
        p.key.startswith("(cname-cloak)") for p in imio[0].params
    )


def test_imio_hosting_does_not_trigger_evasion_in_privacy() -> None:
    """The whole-site hosting CNAME must not be marked as cloak/evasion
    or count IMIO as a third-party tracker module (no forwarded vendor)."""
    from leak_inspector.report.score_v2 import _forwarded_vendor_module_ids

    event = _request("www.ciney.be", path="/home")
    analysis = analyze_events(
        _manifest(), [event], cname_chains=_IMIO_CHAIN,
    )
    # No hit is cloak/proxy-marked → no forwarded vendor → no evasion cost.
    assert _forwarded_vendor_module_ids(analysis) == set()
    # IMIO is first-party hosting, not a counted third-party module.
    assert "paragov_imio" not in {
        h.module_id for h in analysis.hits
        if any(p.key.startswith("(cname-cloak)") for p in h.params)
    }


def test_real_tracker_cname_cloak_still_marked() -> None:
    """Guard: a genuine tracker (Piano/AT Internet) cloaked behind a
    first-party alias must STILL get the cloak marker — the gate keys on
    module kind, not on CNAME matching in general."""
    event = _request("stats.ciney.be", path="/hit.xiti", query="s=1")
    analysis = analyze_events(
        _manifest(), [event],
        cname_chains={"stats.ciney.be": ["stats.ciney.be", "logs.at-o.net"]},
    )
    piano = [h for h in analysis.hits if h.module_id == "piano_analytics"]
    assert piano, "real cloaked tracker should be attributed"
    assert any(p.key.startswith("(cname-cloak)") for p in piano[0].params)
