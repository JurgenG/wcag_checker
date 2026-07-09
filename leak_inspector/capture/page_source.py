"""Persist page source and referenced script bodies alongside screenshots.

Whenever the recorder takes a screenshot it also calls
:func:`capture_page_source`, which writes three artifacts into the
session directory (picked up verbatim by :func:`write_bundle`):

* ``page_source{suffix}.html`` — the live DOM serialized via
  ``driver.page_source``, stored raw so ``<script integrity>`` attributes
  and full markup survive for offline analysis.
* ``scripts/<sha256>`` — the body of each ``<script src>`` the page
  references, content-addressed and deduplicated.
* ``page_source{suffix}.scripts.json`` — an index with one row per
  enumerated subresource (``<script src>`` *and*
  ``<link rel=stylesheet href>``): ``url`` / ``integrity`` /
  ``crossorigin`` / ``kind`` (``"script"`` | ``"stylesheet"``) plus the
  stored ``sha256`` (``None`` when the body could not be fetched) and a
  ``status`` string. Stylesheets are enumerated for SRI analysis only —
  their bodies are not fetched (``status="not-fetched"``).

Subresource *enumeration* runs in-browser (read-only
``querySelectorAll``, no network), but script *bodies* are fetched
**server-side** so the fetch neither hits CORS nor pollutes the
BiDi-recorded event stream. Every step soft-fails: a missing artifact
never aborts the capture.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any, Callable

from ..safe_net import build_safe_opener, is_public_url

#: Read-only DOM query returning one record per ``<script src>`` /
#: ``<link rel=stylesheet href>`` element, with the resolved absolute
#: URL, the SRI-relevant attributes, and the element kind. Runs via
#: ``execute_script`` so dynamically-injected subresources are included.
_ENUMERATE_SCRIPTS_JS = (
    "return Array.from(document.querySelectorAll("
    "'script[src], link[rel=stylesheet][href]')).map("
    "function (el) { var link = el.tagName === 'LINK'; "
    "return {url: link ? el.href : el.src, "
    "kind: link ? 'stylesheet' : 'script', "
    "integrity: el.integrity || null, "
    "crossorigin: el.crossOrigin || null}; });"
)

#: Cap on a single fetched script body. Bodies larger than this are
#: skipped (recorded as ``too-large``) rather than truncated, since a
#: truncated body would carry a meaningless hash.
_SCRIPT_FETCH_CAP_BYTES = 16 * 1024 * 1024

_FETCH_TIMEOUT_SECONDS = 10

#: Result of one body fetch: ``(body_or_None, status_string)``.
FetchResult = tuple[bytes | None, str]
Fetcher = Callable[[str], FetchResult]

#: Shared opener that re-validates every redirect ``Location`` against
#: ``is_public_url`` before following — see ``leak_inspector.safe_net``.
_OPENER = build_safe_opener()


def _fetch_script_body(url: str) -> FetchResult:
    """Fetch ``url`` server-side, returning ``(bytes | None, status)``.

    Best-effort: any network/HTTP error yields ``(None, "<reason>")`` so
    the caller records the gap without the body. Bodies over
    :data:`_SCRIPT_FETCH_CAP_BYTES` are skipped as ``too-large``.

    The ``url`` comes verbatim from the visited page's ``<script src>``
    markup, which is untrusted. Refuses anything that is not an
    ``http``/``https`` URL resolving to a public address — blocking
    ``file://`` local-file reads and SSRF to loopback / private /
    link-local / cloud-metadata endpoints — and follows redirects only
    through the SSRF-checked opener. See ``leak_inspector.safe_net`` for
    the threat model (the analysis-time probes share it).
    """
    if not is_public_url(url):
        return None, "blocked-non-public-url"
    request = urllib.request.Request(url, headers={"User-Agent": "leak-inspector"})
    try:
        with _OPENER.open(request, timeout=_FETCH_TIMEOUT_SECONDS) as resp:
            body = resp.read(_SCRIPT_FETCH_CAP_BYTES + 1)
            status = str(getattr(resp, "status", "") or resp.getcode())
    except Exception as exc:  # noqa: BLE001 -- best-effort, never abort capture
        return None, type(exc).__name__
    if len(body) > _SCRIPT_FETCH_CAP_BYTES:
        return None, "too-large"
    return body, status


def capture_page_source(
    driver: Any,
    session_dir: Path,
    *,
    suffix: str = "",
    fetch: Fetcher = _fetch_script_body,
) -> None:
    """Write page source + referenced script bodies for one screenshot.

    ``suffix`` mirrors the screenshot filename suffix (``""`` for the
    post-load capture, ``_<host>_<HHMMSS>`` for operator-triggered ones).
    ``fetch`` is injectable for testing. Soft-fails throughout.
    """
    session_dir = Path(session_dir)

    try:
        html = driver.page_source
    except Exception:  # noqa: BLE001 -- soft-fail: a dead session loses nothing else
        html = None
    if html is not None:
        try:
            (session_dir / f"page_source{suffix}.html").write_text(
                html, encoding="utf-8")
        except OSError:  # pragma: no cover -- disk full / read-only
            pass

    try:
        scripts = driver.execute_script(_ENUMERATE_SCRIPTS_JS) or []
    except Exception:  # noqa: BLE001 -- soft-fail to an empty index
        scripts = []

    index = [_persist_script(entry, session_dir, fetch) for entry in scripts]

    try:
        (session_dir / f"page_source{suffix}.scripts.json").write_text(
            json.dumps(index), encoding="utf-8")
    except OSError:  # pragma: no cover -- disk full / read-only
        pass


def _persist_script(entry: dict, session_dir: Path, fetch: Fetcher) -> dict:
    """Build one subresource's index row; fetch + store script bodies.

    Stylesheets are indexed (the SRI analysis needs ``url`` +
    ``integrity``) but their bodies are not fetched. A record with no
    ``kind`` is a script — every record was, before stylesheet
    enumeration existed.
    """
    url = entry.get("url")
    kind = entry.get("kind") or "script"
    sha: str | None = None
    if kind == "stylesheet":
        status = "not-fetched"
    else:
        body, status = fetch(url)
        if body is not None:
            sha = hashlib.sha256(body).hexdigest()
            scripts_dir = session_dir / "scripts"
            try:
                scripts_dir.mkdir(exist_ok=True)
                target = scripts_dir / sha
                if not target.exists():
                    target.write_bytes(body)
            except OSError:  # pragma: no cover -- disk full / read-only
                sha = None
                status = "store-error"
    return {
        "url": url,
        "integrity": entry.get("integrity"),
        "crossorigin": entry.get("crossorigin"),
        "kind": kind,
        "sha256": sha,
        "status": status,
    }