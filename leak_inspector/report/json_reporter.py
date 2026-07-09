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

"""Machine-readable JSON reporter.

A thin pass through the :class:`~.document.ReportDocument` — the
single source of truth that the text, markdown, and HTML reporters
also consume. Downstream tools (CMP dashboards, CI gates, periodic
audits) get every piece of information any other format renders, in
a structured form.

Schema is documented in :mod:`.document`. The version number is
exposed at the document root so a consumer can reject unknown
versions or branch on them.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from ..analysis import Analysis
from .builder import build_report_document
from .document import ReportDocument


def write_json_report(
    analysis: Analysis,
    *,
    indent: int | None = 2,
    display_name: str | None = None,
) -> str:
    """Render ``analysis`` as a JSON document.

    The output is :func:`json.dumps` of :func:`build_report_document`'s
    asdict form. ``indent`` controls pretty-printing; pass ``None`` for
    the most compact form. ``display_name`` overrides the report title
    in the document manifest (the bulk tool's name-column feature).
    """
    document = build_report_document(analysis, display_name=display_name)
    return write_document_json(document, indent=indent)


def write_document_json(
    document: ReportDocument,
    *,
    indent: int | None = 2,
) -> str:
    """Serialize an already-built :class:`ReportDocument` to JSON."""
    return json.dumps(asdict(document), indent=indent, sort_keys=True)


__all__ = ["write_document_json", "write_json_report"]
