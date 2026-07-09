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

"""RFC 9116 ``security.txt`` presence probe (enrichment phase).

A published ``/.well-known/security.txt`` gives security researchers a
machine-readable way to reach the operator — a small but telling
posture signal (OpenKAT and internet.nl both check it). One fetch, run
once at enrichment time and stored in the bundle's artifact.

"Present" is a guarded claim (certain-data rule): municipal sites
routinely serve HTML error pages with status 200, so presence requires
status 200 **and** a ``text/plain`` content type (RFC 9116 §3) **and**
a ``Contact:`` field — the only field the RFC REQUIRES. The raw
signals (``status`` / ``content_type`` / ``has_contact``) are recorded
alongside the verdict so a report can distinguish "absent" from
"present but malformed".

The live fetch goes through :mod:`leak_inspector.safe_net` (public-URL
gate, pinned connections, SSRF-checked redirects) — the host comes
from an untrusted bundle manifest.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from ..safe_net import build_safe_opener, is_public_url

#: A security.txt is a handful of lines; anything bigger is not one.
_FETCH_CAP_BYTES = 64 * 1024

_FETCH_TIMEOUT_SECONDS = 10

#: ``Contact:`` at the start of a line, case-insensitive (RFC 9116
#: field names are case-insensitive; mid-prose mentions don't count).
_CONTACT_FIELD = re.compile(r"^contact:", re.I | re.M)

#: One probe fetch: ``url -> (status | None, content_type, body)``.
Fetcher = Callable[[str], tuple[int | None, str, str]]

_OPENER = build_safe_opener()


@dataclass
class SecurityTxtProbe:
    """Result of the ``security.txt`` presence probe for one host.

    ``found`` is the guarded verdict; ``status`` / ``content_type`` /
    ``has_contact`` are the raw signals it was derived from.
    ``status`` is ``None`` when the host never answered.
    """

    url: str
    found: bool = False
    status: int | None = None
    content_type: str = ""
    has_contact: bool = False


def _live_fetch(url: str) -> tuple[int | None, str, str]:
    """Fetch ``url`` via the SSRF-guarded opener; never raises upward."""
    if not is_public_url(url):
        return None, "", ""
    request = urllib.request.Request(
        url, headers={"User-Agent": "leak-inspector"},
    )
    try:
        with _OPENER.open(request, timeout=_FETCH_TIMEOUT_SECONDS) as resp:
            body = resp.read(_FETCH_CAP_BYTES)
            status = int(getattr(resp, "status", None) or resp.getcode())
            content_type = resp.headers.get("Content-Type", "") or ""
    except urllib.error.HTTPError as exc:
        return exc.code, "", ""
    except Exception:  # noqa: BLE001 -- soft-fail: posture, not data
        return None, "", ""
    return status, content_type, body.decode("utf-8", "replace")


def probe_security_txt(
    host: str,
    *,
    fetcher: Fetcher | None = None,
) -> SecurityTxtProbe:
    """Probe ``https://<host>/.well-known/security.txt`` once.

    Returns a :class:`SecurityTxtProbe`; never raises. ``fetcher`` is
    injectable for tests (the default is the live SSRF-guarded fetch).
    """
    fetcher = fetcher or _live_fetch
    url = f"https://{host}/.well-known/security.txt"
    try:
        status, content_type, body = fetcher(url)
    except Exception:  # noqa: BLE001 -- a broken fetcher is "unreachable"
        status, content_type, body = None, "", ""
    has_contact = bool(_CONTACT_FIELD.search(body or ""))
    found = (
        status == 200
        and content_type.lower().startswith("text/plain")
        and has_contact
    )
    return SecurityTxtProbe(
        url=url,
        found=found,
        status=status,
        content_type=content_type,
        has_contact=has_contact,
    )


__all__ = ["SecurityTxtProbe", "probe_security_txt"]
