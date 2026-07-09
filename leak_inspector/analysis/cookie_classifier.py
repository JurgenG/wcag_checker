"""Map well-known cookie names to the tracker that sets them.

Tracker cookies set client-side via ``document.cookie`` (GA's ``_ga``,
Meta's ``_fbp``, …) are first-party by domain, so the request-module
machinery — which classifies by host/path — never attributes them. This
module recognises them by their documented names and resolves each to
the stable ``module_id`` the request modules also use, keeping a single
vendor vocabulary so the cookie can be linked back to a forwarding /
cloaking hit during scoring.

Only certain, documented names are listed (the certain-data rule); an
unrecognised name returns ``None`` rather than a guess.
"""

from __future__ import annotations

import re

#: ``(compiled name pattern, module_id, display label)``. Patterns are
#: anchored and boundary-aware so a tracker prefix never swallows an
#: unrelated cookie (``_gafoo`` must not read as ``_ga``). First match
#: wins; the set is deliberately small and well-known.
_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^_ga(_[A-Za-z0-9]+)?$"), "ga4", "Google Analytics"),
    (re.compile(r"^_gid$"), "ga4", "Google Analytics"),
    (re.compile(r"^_gat(_.*)?$"), "ga4", "Google Analytics"),
    (re.compile(r"^_fb[pc]$"), "facebook_pixel", "Meta Pixel"),
    (re.compile(r"^_gcl_[a-z]{2}$"), "google_ads", "Google Ads"),
    (re.compile(r"^_cl(ck|sk)$"), "clarity", "Microsoft Clarity"),
    (re.compile(r"^_hj[A-Za-z]"), "hotjar", "Hotjar"),
    (re.compile(r"^_pk_(id|ses)(\.|$)"), "matomo", "Matomo"),
    (re.compile(r"^AMCVS?_"), "adobe_marketing_cloud", "Adobe Experience Cloud"),
]


def classify_cookie_tracker(name: str) -> tuple[str, str] | None:
    """Return ``(module_id, display_label)`` for a known tracker cookie.

    ``None`` when the name is not a recognised tracker cookie — benign
    first-party cookies (session IDs, language, consent state) fall
    through here and are never attributed to a vendor.
    """
    if not name:
        return None
    for pattern, module_id, label in _PATTERNS:
        if pattern.match(name):
            return module_id, label
    return None
