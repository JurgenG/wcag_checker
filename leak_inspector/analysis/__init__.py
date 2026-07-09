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

"""Run tracker modules over a capture bundle.

Iterates the bundle's normalized event stream, dispatches to registered
tracker modules, and produces an :class:`Analysis` suitable for the
reporters. Repeat hits are collapsed by the spec's dedup rule
``(module_id, endpoint, param-key-set, event-type)`` via
:meth:`Analysis.representative_hits`.

Must not import from ``leak_inspector.capture``: analysis only reads
bundles.
"""

from .operator_families import FAMILIES, operator_label, same_operator
from .runner import Analysis, analyze_bundle, analyze_events

__all__ = [
    "Analysis",
    "FAMILIES",
    "analyze_bundle",
    "analyze_events",
    "operator_label",
    "same_operator",
]
