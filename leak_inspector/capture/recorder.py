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

"""Capture session orchestration.

A :class:`Recorder` ties together the four capture-layer pieces — driver
(:mod:`.driver`), BiDi capture (:mod:`.bidi`), storage snapshots
(:mod:`.storage`), and the bundle writer (:mod:`leak_inspector.bundle`) —
into one :meth:`Recorder.run` call. The user manually drives Firefox;
the recorder records the session.

End-of-session is signaled by the user closing the Firefox window. The
recorder polls ``driver.window_handles`` on a short interval and stops
when the list is empty or the session is invalidated. A keyboard
interrupt (Ctrl-C) is also accepted as a fallback.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import threading
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TextIO

import tldextract
from selenium.common.exceptions import WebDriverException

from .. import __version__ as _TOOL_VERSION
from ..bundle import Manifest, write_bundle
from ..bundle.manifest import BUNDLE_SCHEMA_VERSION, TOOL_NAME
from . import EventIdCounter
from .bidi import BiDiCapture
from .dns import collect_chains
from .driver import LaunchedDriver, launch_driver
from .page_source import capture_page_source
from .storage import take_snapshot


#: How often to poll for browser-close and URL changes.
DEFAULT_POLL_INTERVAL_SECONDS = 0.5

#: Unattended-capture settle defaults. Rather than a fixed sleep from
#: the page-load event (which fires before deferred scripts, framework
#: hydration and consent banners render), the unattended path waits
#: until the BiDi event stream goes quiet — no new event for
#: ``IDLE_WINDOW`` seconds — capped at ``MAX_WAIT`` seconds so a page
#: that polls forever still finalises.
DEFAULT_SETTLE_IDLE_WINDOW_SECONDS = 2.0
DEFAULT_SETTLE_MAX_WAIT_SECONDS = 15.0


@dataclass
class RecorderResult:
    """Summary of what :meth:`Recorder.run` produced."""

    bundle_path: Path
    session_id: str
    started_at: str
    ended_at: str
    event_count: int


class Recorder:
    """Run one end-to-end capture session and produce a bundle zip.

    Construct with the target URL and output path, then call :meth:`run`.
    Optional ``profile_path`` swaps the default fresh temporary profile
    for an existing Firefox profile (the profile is used **in place** —
    see :func:`.driver.launch_driver`).

    ``work_dir`` overrides the temporary session directory (mostly for
    tests and debugging — production runs let the recorder pick a fresh
    one and clean it up).

    ``auto_close_after_load`` switches the session from human-driven
    (poll until the window is closed) to unattended: after
    ``driver.get`` returns, wait for the page to settle, then finalize.
    Used by the bulk-tool runner. Settling waits until the BiDi event
    stream is quiet for ``settle_idle_window`` seconds (so deferred
    scripts and consent banners have rendered), capped at
    ``settle_max_wait``. ``auto_close_after_load`` is kept as a minimum
    settle floor (the wait is never shorter than this), preserving the
    old "always wait at least N seconds" guarantee.

    ``headless`` runs Firefox without a visible window. Only intended
    for bulk / unattended captures — see :func:`.driver.launch_driver`.
    """

    def __init__(
        self,
        target_url: str,
        out_path: Path | str,
        *,
        profile_path: Path | str | None = None,
        work_dir: Path | str | None = None,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
        auto_close_after_load: float | None = None,
        settle_idle_window: float = DEFAULT_SETTLE_IDLE_WINDOW_SECONDS,
        settle_max_wait: float = DEFAULT_SETTLE_MAX_WAIT_SECONDS,
        headless: bool = False,
    ) -> None:
        self._target_url = target_url
        self._out_path = Path(out_path)
        self._profile_path = Path(profile_path) if profile_path else None
        self._work_dir_override = Path(work_dir) if work_dir else None
        self._poll_interval = poll_interval
        self._auto_close_after_load = auto_close_after_load
        self._settle_idle_window = settle_idle_window
        self._settle_max_wait = settle_max_wait
        self._headless = headless
        # Serializes snapshot calls between the main poll loop and the
        # BiDi pre-navigation callback (which runs on a Selenium-internal
        # thread). Both append to the same ``storage/<host>.json`` file.
        self._snapshot_lock = threading.Lock()

    # --- entry point -------------------------------------------------------

    def run(self) -> RecorderResult:
        """Drive the full capture and return where the bundle was written."""
        session_id, started_at = self._new_session_id()
        session_dir = self._prepare_session_dir(session_id)
        events_log_path = session_dir / "events.jsonl"
        events_log = events_log_path.open("a", encoding="utf-8")
        next_event_id = EventIdCounter()
        sink, get_count = self._make_sink(events_log)

        browser_version = ""
        ended_at: str | None = None
        landing_url = self._target_url
        try:
            launched = launch_driver(self._profile_path, headless=self._headless)
            try:
                browser_version = self._read_browser_version(launched.driver)
                bidi = BiDiCapture(launched.driver, sink, next_event_id=next_event_id)
                # Pre-navigation snapshot: BiDi fires ``navigationStarted``
                # while the old page is still JS-accessible (briefly).
                # Calling execute_script from a BiDi callback thread is
                # best-effort — Selenium's Marionette client is generally
                # safe for read-only commands, and any failure is swallowed
                # by BiDiCapture so capture keeps running.
                bidi.pre_navigation_callback = self._make_pre_nav_snapshot(
                    driver=launched.driver,
                    session_dir=session_dir,
                    next_event_id=next_event_id,
                    sink=sink,
                )
                bidi.screenshot_requested_callback = self._make_screenshot_callback(
                    driver=launched.driver,
                    session_dir=session_dir,
                )
                try:
                    bidi.start()
                except Exception as exc:
                    raise RuntimeError(
                        "failed to start BiDi subscriptions — Selenium >= 4.27 "
                        f"and a BiDi-capable Firefox are required: {exc}"
                    ) from exc

                with suppress(WebDriverException):
                    launched.driver.get(self._target_url)

                # Capture the landing URL right after the initial-page
                # load settles. ``driver.get`` blocks until the load
                # event, so by this point any HTTP 3xx + sync-during-load
                # JS redirects have already resolved and ``current_url``
                # reflects the actual host that owns this session.
                landing_url = self._target_url
                with suppress(WebDriverException):
                    landing_url = launched.driver.current_url or self._target_url

                # One PNG screenshot of the visitor's first impression —
                # taken right after the page-load event fires, before
                # entering the wait / interaction phase. Soft-fails so a
                # Selenium hiccup never aborts the capture.
                self._capture_screenshot(launched.driver, session_dir)

                if self._auto_close_after_load is not None:
                    self._wait_after_load(
                        driver=launched.driver,
                        session_dir=session_dir,
                        next_event_id=next_event_id,
                        sink=sink,
                        activity_count=get_count,
                    )
                else:
                    self._poll_until_browser_closed(
                        driver=launched.driver,
                        session_dir=session_dir,
                        next_event_id=next_event_id,
                        sink=sink,
                    )

                # Stop BiDi while the driver is still alive — so listener
                # removal can talk to the browser cleanly.
                with suppress(Exception):
                    bidi.stop()
            finally:
                launched.close()
            ended_at = self._now_iso()
        finally:
            events_log.close()

        # Resolve CNAME chains for every unique hostname seen this
        # session. Done after events.jsonl is closed (so we can re-read
        # it) and before bundle finalization (so the writer picks the
        # output file up automatically). The cost is bounded by the
        # per-query timeout in :mod:`.dns`; a network outage at this
        # point cannot block bundle write indefinitely.
        self._write_cname_chains(session_dir, events_log_path)

        # base_domain comes from the landing URL (post-redirect) so the
        # third-party / first-party classifier uses the operator's actual
        # host, not the (often-redirected) entry-point URL the operator
        # passed on the command line. Falls back to target_url when
        # ``driver.get`` failed and we never got a landing.
        effective_first_party = landing_url or self._target_url
        manifest = Manifest(
            bundle_schema=BUNDLE_SCHEMA_VERSION,
            tool=TOOL_NAME,
            tool_version=_TOOL_VERSION,
            session_id=session_id,
            started_at=started_at,
            ended_at=ended_at or self._now_iso(),
            target_url=self._target_url,
            landing_url=landing_url,
            base_domain=_base_domain(effective_first_party),
            browser={"name": "firefox", "version": browser_version},
            profile=str(self._profile_path) if self._profile_path else "fresh",
        )
        bundle_path = write_bundle(session_dir, manifest, self._out_path)
        return RecorderResult(
            bundle_path=bundle_path,
            session_id=session_id,
            started_at=started_at,
            ended_at=manifest.ended_at,
            event_count=get_count(),
        )

    # --- internals ---------------------------------------------------------

    def _poll_until_browser_closed(
        self,
        *,
        driver: Any,
        session_dir: Path,
        next_event_id: EventIdCounter,
        sink: Callable[[dict], None],
    ) -> None:
        """Block until the user closes the browser window or sends Ctrl-C.

        While blocked, snapshot storage every time the top-level URL changes.
        Emits a final best-effort snapshot before returning.
        """
        last_url: str | None = None
        try:
            while True:
                try:
                    handles = driver.window_handles
                except WebDriverException:
                    break  # Session invalidated — usually means window closed.
                if not handles:
                    break

                with suppress(WebDriverException):
                    current_url = driver.current_url
                    if current_url != last_url:
                        last_url = current_url
                        with self._snapshot_lock:
                            take_snapshot(
                                driver,
                                session_dir,
                                next_event_id=next_event_id,
                                event_sink=sink,
                            )

                time.sleep(self._poll_interval)
        except KeyboardInterrupt:
            print("interrupt received — finalizing session", file=sys.stderr)

        # Final snapshot while the driver may still be alive. This is the
        # one chance to catch end-of-session state on the last page; it
        # often fails silently when the window has already gone away,
        # which is fine.
        with suppress(Exception):
            with self._snapshot_lock:
                take_snapshot(
                    driver,
                    session_dir,
                    next_event_id=next_event_id,
                    event_sink=sink,
                )

    def _wait_after_load(
        self,
        *,
        driver: Any,
        session_dir: Path,
        next_event_id: EventIdCounter,
        sink: Callable[[dict], None],
        activity_count: Callable[[], int],
    ) -> None:
        """Unattended end-of-session: snapshot, settle, snapshot, return.

        Used when :class:`Recorder` is constructed with
        ``auto_close_after_load``. ``driver.get`` blocks only until the
        page-load event — which fires before deferred scripts, framework
        hydration and consent banners have rendered. So instead of a
        fixed sleep we wait until the BiDi event stream goes quiet (no
        new event for ``settle_idle_window`` seconds), capped at
        ``settle_max_wait``; ``auto_close_after_load`` acts as a minimum
        floor. The closing snapshot then records the settled cookie /
        storage state (e.g. a banner's on-render cookie).
        """
        with suppress(Exception):
            with self._snapshot_lock:
                take_snapshot(
                    driver,
                    session_dir,
                    next_event_id=next_event_id,
                    event_sink=sink,
                )

        self._wait_for_network_idle(
            activity_count=activity_count,
            now=time.monotonic,
            sleep=time.sleep,
            idle_window=self._settle_idle_window,
            max_wait=self._settle_max_wait,
            poll=self._poll_interval,
            min_wait=self._auto_close_after_load or 0.0,
        )

        with suppress(Exception):
            with self._snapshot_lock:
                take_snapshot(
                    driver,
                    session_dir,
                    next_event_id=next_event_id,
                    event_sink=sink,
                )

    @staticmethod
    def _wait_for_network_idle(
        *,
        activity_count: Callable[[], int],
        now: Callable[[], float],
        sleep: Callable[[float], None],
        idle_window: float,
        max_wait: float,
        poll: float,
        min_wait: float = 0.0,
    ) -> float:
        """Block until the event stream is quiet, return seconds waited.

        Polls ``activity_count`` (a monotonic count of BiDi events seen
        so far) every ``poll`` seconds. Settles once no new event has
        arrived for ``idle_window`` seconds — but never before
        ``min_wait`` and never after ``max_wait`` (the hard cap that
        stops a forever-polling page from blocking the run). Pure: the
        clock and sleep are injected so it is deterministically
        testable.
        """
        start = now()
        last_change = start
        last_count = activity_count()
        while True:
            sleep(poll)
            current = now()
            elapsed = current - start
            count = activity_count()
            if count != last_count:
                last_count = count
                last_change = current
            quiet_for = current - last_change
            if elapsed >= max_wait:
                return elapsed
            if quiet_for >= idle_window and elapsed >= min_wait:
                return elapsed

    def _make_pre_nav_snapshot(
        self,
        *,
        driver: Any,
        session_dir: Path,
        next_event_id: EventIdCounter,
        sink: Callable[[dict], None],
    ) -> Callable[[dict], None]:
        """Build the pre-navigation snapshot callback for :class:`BiDiCapture`.

        Fires on every ``navigationStarted`` event, before the navigation
        event itself is emitted. Captures whatever the outgoing page's
        JavaScript context is still willing to expose. Guarded by the
        shared snapshot lock so it serializes with main-loop snapshots.
        """
        def hook(_bidi_event: dict) -> None:
            with self._snapshot_lock:
                take_snapshot(
                    driver,
                    session_dir,
                    next_event_id=next_event_id,
                    event_sink=sink,
                )

        return hook

    def _make_screenshot_callback(
        self,
        *,
        driver: Any,
        session_dir: Path,
    ) -> Callable[[str], None]:
        """Build the screenshot-on-demand callback for :class:`BiDiCapture`.

        Fires when the in-page key-down handler hits the sentinel URL.
        Acquires the shared snapshot lock so a press during an active
        storage snapshot serializes cleanly.
        """
        def hook(host: str) -> None:
            hhmmss = datetime.now(timezone.utc).strftime("%H%M%S")
            with self._snapshot_lock:
                self._capture_extra_screenshot(
                    driver, session_dir, host=host, hhmmss=hhmmss,
                )

        return hook

    @staticmethod
    def _make_sink(fh: TextIO) -> tuple[Callable[[dict], None], Callable[[], int]]:
        """Build a thread-safe sink that writes JSONL to ``fh`` and counts events."""
        lock = threading.Lock()
        count = [0]

        def sink(event: dict) -> None:
            line = json.dumps(event, ensure_ascii=False)
            with lock:
                fh.write(line + "\n")
                fh.flush()
                count[0] += 1

        def get_count() -> int:
            with lock:
                return count[0]

        return sink, get_count

    def _new_session_id(self) -> tuple[str, str]:
        """Return ``(session_id, started_at_iso)``."""
        now = datetime.now(timezone.utc)
        timestamp_compact = now.strftime("%Y-%m-%dT%H-%M-%SZ")
        session_id = f"{timestamp_compact}-{uuid.uuid4().hex[:6]}"
        started_at = now.isoformat().replace("+00:00", "Z")
        return session_id, started_at

    def _prepare_session_dir(self, session_id: str) -> Path:
        """Create (or reuse) the working directory for this session."""
        if self._work_dir_override is not None:
            path = self._work_dir_override
        else:
            path = Path(
                tempfile.mkdtemp(prefix=f"leak_inspector_session_{session_id}_")
            )
        path.mkdir(parents=True, exist_ok=True)
        (path / "storage").mkdir(exist_ok=True)
        (path / "scripts").mkdir(exist_ok=True)
        # Touch events.jsonl so the bundle writer's existence check passes
        # even on a session that fired zero BiDi events (very unusual).
        (path / "events.jsonl").touch()
        return path

    @staticmethod
    def _write_cname_chains(session_dir: Path, events_log_path: Path) -> None:
        """Resolve CNAME chains for every host in ``events.jsonl`` and write ``cname_chains.json``.

        Reads the already-finalized events log, collects unique
        hostnames from request events, fires parallel DNS queries via
        :func:`.dns.collect_chains`, and writes a sorted JSON mapping
        ``{hostname: [chain, ...]}`` into the session directory so the
        bundle writer zips it in.

        Best-effort: any exception while reading the log or doing DNS
        is caught and logged to stderr, leaving the session-finalize
        path intact. A bundle without ``cname_chains.json`` is still a
        valid bundle (older bundles never had this file).
        """
        try:
            hosts: set[str] = set()
            with events_log_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("type") != "request":
                        continue
                    host = (event.get("payload") or {}).get("host")
                    if host:
                        hosts.add(host)
            if not hosts:
                return
            print(
                f"resolving CNAME chains for {len(hosts)} unique hosts…",
                file=sys.stderr,
            )
            start = time.monotonic()
            chains = collect_chains(hosts)
            elapsed = time.monotonic() - start
            cloaked = sum(1 for chain in chains.values() if len(chain) > 1)
            print(
                f"DNS done in {elapsed:.1f}s "
                f"({cloaked} host{'s' if cloaked != 1 else ''} with CNAME aliasing)",
                file=sys.stderr,
            )
            out = session_dir / "cname_chains.json"
            out.write_text(
                json.dumps(
                    {host: chains[host] for host in sorted(chains)},
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception as exc:
            print(
                f"warning: CNAME chain collection failed: {exc}",
                file=sys.stderr,
            )

    @staticmethod
    def _read_browser_version(driver: Any) -> str:
        try:
            return str(driver.capabilities.get("browserVersion") or "")
        except Exception:
            return ""

    @staticmethod
    def _capture_screenshot(driver: Any, session_dir: Path) -> None:
        """Take one viewport-sized PNG and drop it at the bundle root.

        Soft-fails on every WebDriver error: a missing screenshot is
        strictly better than a missing capture. The file lands in
        ``session_dir/screenshot.png`` so :func:`write_bundle` picks it
        up automatically alongside ``manifest.json`` and ``events.jsonl``.
        Once the PNG lands, :func:`capture_page_source` records the matching
        page source + referenced script bodies (suffix ``""``).
        """
        try:
            png_bytes = driver.get_screenshot_as_png()
        except WebDriverException:
            return
        except Exception:  # pragma: no cover -- defensive
            return
        if not png_bytes:
            return
        try:
            (session_dir / "screenshot.png").write_bytes(png_bytes)
        except OSError:  # pragma: no cover -- disk full / read-only
            return
        capture_page_source(driver, session_dir, suffix="")

    @staticmethod
    def _capture_extra_screenshot(
        driver: Any, session_dir: Path, *, host: str, hhmmss: str,
    ) -> None:
        """Take an ad-hoc PNG triggered by the operator's keyboard shortcut.

        Writes ``screenshot_<host>_<HHMMSS>.png`` into ``session_dir`` so
        :func:`write_bundle` zips it alongside the post-load
        ``screenshot.png``. ``host`` is sanitized to a safe filename
        fragment — path-traversal characters are stripped and the empty
        host falls back to the literal ``unknown``. Soft-fails on every
        WebDriver / OS error so this never aborts the capture loop. Once the
        PNG lands, :func:`capture_page_source` records the matching page
        source + referenced script bodies under the same suffix.
        """
        try:
            png_bytes = driver.get_screenshot_as_png()
        except WebDriverException:
            return
        except Exception:  # pragma: no cover -- defensive
            return
        if not png_bytes:
            return
        safe_host = _sanitize_host_for_filename(host) or "unknown"
        suffix = f"_{safe_host}_{hhmmss}"
        target = session_dir / f"screenshot{suffix}.png"
        try:
            target.write_bytes(png_bytes)
        except OSError:  # pragma: no cover -- disk full / read-only
            return
        capture_page_source(driver, session_dir, suffix=suffix)

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _base_domain(url: str) -> str:
    """Derive the first-party base domain (registrable domain) for ``url``."""
    extracted = tldextract.extract(url)
    return ".".join(part for part in (extracted.domain, extracted.suffix) if part)


def _sanitize_host_for_filename(host: str) -> str:
    """Strip a hostname down to a safe filename fragment.

    Accepts host strings that may have come from operator-controlled
    page JavaScript (the sentinel URL's ``?host=`` is set from
    ``location.host`` but a misbehaving site can override that).
    Keeps only ``[A-Za-z0-9.-]`` (the safe DNS-host alphabet), then
    collapses any ``..`` runs (defence-in-depth against the substring
    appearing in a filename — ``pathlib`` already prevents traversal,
    but a literal ``..`` in a filename is also visually misleading).
    """
    cleaned = re.sub(r"[^A-Za-z0-9.\-]", "", host or "")
    while ".." in cleaned:
        cleaned = cleaned.replace("..", ".")
    return cleaned.strip(".-")


__all__ = [
    "DEFAULT_POLL_INTERVAL_SECONDS",
    "Recorder",
    "RecorderResult",
]
