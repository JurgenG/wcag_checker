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

"""Reporters: JSON, text, markdown, HTML.

All four reporters consume a single :class:`~.document.ReportDocument`
built once from an :class:`~leak_inspector.analysis.Analysis`. The
JSON reporter is the canonical serialization of that document; the
text / markdown / HTML reporters walk it and emit format-specific
rendering.

To render: call ``write_<format>_report(analysis)`` for the entry
point, or build the document yourself with :func:`build_report_document`
and call ``render_<format>_document(doc, ...)``.
"""

from .builder import build_report_document
from .debug import collect_unknown_hosts, write_debug_report
from .document import ReportDocument
from .html import render_html_document, write_html_report
from .json_reporter import write_document_json, write_json_report
from .markdown import (
    render_markdown_document,
    write_markdown_detailed,
    write_markdown_summary,
)
from .text import render_text_document, write_text_report

__all__ = [
    "ReportDocument",
    "build_report_document",
    "collect_unknown_hosts",
    "render_html_document",
    "render_markdown_document",
    "render_text_document",
    "write_debug_report",
    "write_document_json",
    "write_html_report",
    "write_json_report",
    "write_markdown_detailed",
    "write_markdown_summary",
    "write_text_report",
]
