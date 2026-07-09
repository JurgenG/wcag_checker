"""Network-idle settle for unattended (bulk) capture.

The old unattended path slept a fixed 1 s measured from the page-load
event — which fires before deferred scripts, framework hydration and
consent banners have rendered, so the capture closed before the page
had actually settled. The replacement waits until the BiDi event
stream goes quiet (no new event for ``idle_window`` seconds), capped
at ``max_wait``.

The core is a pure loop driven by an injected clock / sleep / event
counter, so these tests are deterministic and touch no browser.
"""

from __future__ import annotations

from leak_inspector.capture.recorder import Recorder


class _FakeClock:
    """Monotonic clock whose ``sleep`` advances it and feeds a count."""

    def __init__(self, activity_schedule: dict[float, int]) -> None:
        # Map of time -> cumulative event count reached *by* that time.
        self._schedule = dict(activity_schedule)
        self._t = 0.0
        self._count = activity_schedule.get(0.0, 0)

    def now(self) -> float:
        return self._t

    def sleep(self, seconds: float) -> None:
        self._t += seconds
        for at in sorted(self._schedule):
            if at <= self._t:
                self._count = self._schedule[at]

    def count(self) -> int:
        return self._count


def _wait(schedule, *, idle_window=2.0, max_wait=15.0, poll=0.5) -> float:
    clock = _FakeClock(schedule)
    return Recorder._wait_for_network_idle(
        activity_count=clock.count,
        now=clock.now,
        sleep=clock.sleep,
        idle_window=idle_window,
        max_wait=max_wait,
        poll=poll,
    )


def test_settles_after_quiet_window() -> None:
    """Activity stops at t=3; settle fires idle_window (2s) later, ~t=5."""
    waited = _wait({0.0: 0, 1.0: 5, 2.0: 9, 3.0: 12})
    assert 4.5 <= waited <= 5.5


def test_immediately_quiet_page_settles_fast() -> None:
    """No activity at all → settles after one idle window, not max_wait."""
    waited = _wait({0.0: 0})
    assert waited <= 2.5


def test_busy_page_is_capped_at_max_wait() -> None:
    """A page that never goes quiet stops at the hard cap."""
    schedule = {float(i): i * 3 for i in range(0, 40)}  # always growing
    waited = _wait(schedule, max_wait=15.0)
    assert 15.0 <= waited <= 15.5


def test_ongoing_activity_then_late_beacon_keeps_window_open() -> None:
    """Steady activity through t=4 (a consent banner injecting requests
    keeps firing) means no full idle window elapses until after t=4 —
    so we settle ~t=6, not at an early lull we never actually had."""
    schedule = {round(0.5 * i, 1): i + 1 for i in range(9)}  # changes 0→4s
    waited = _wait(schedule)
    assert 5.5 <= waited <= 6.5
