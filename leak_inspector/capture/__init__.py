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

"""Selenium + WebDriver BiDi capture layer.

Launches Firefox with stealth prefs, subscribes to BiDi events, snapshots
client-side storage, and writes a capture bundle to disk.

"""

from __future__ import annotations
import threading

class EventIdCounter:
    """Thread-safe monotonic ``event_id`` allocator.

    The capture layer feeds two producers into one ``events.jsonl`` stream:
    BiDi events (network, navigation, log) and storage snapshots. Sharing
    one counter keeps ``event_id`` strictly increasing across both.

    Instances are callable: ``counter()`` returns the next id.
    """

    def __init__(self, start: int = 1) -> None:
        self._next = start
        self._lock = threading.Lock()

    def __call__(self) -> int:
        with self._lock:
            eid = self._next
            self._next += 1
            return eid


__all__ = ["EventIdCounter"]
