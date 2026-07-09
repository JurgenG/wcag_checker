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

"""Capture-agnostic bundle I/O.

Defines the on-disk bundle layout (manifest, events.jsonl, storage
snapshots, script artifacts) and the reader/writer types that produce
and consume it. The normalized event model lives one level up in
:mod:`leak_inspector.events`.

Shared by ``leak_inspector.capture`` and ``leak_inspector.analysis``;
depends on neither.
"""

from .manifest import (
    BUNDLE_SCHEMA_VERSION,
    Manifest,
    ManifestError,
    TOOL_NAME,
)
from .reader import BundleReadError, BundleReader
from .writer import BundleWriteError, write_bundle

__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "BundleReadError",
    "BundleReader",
    "BundleWriteError",
    "Manifest",
    "ManifestError",
    "TOOL_NAME",
    "write_bundle",
]