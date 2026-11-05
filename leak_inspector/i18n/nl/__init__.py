# wcag_checker — record a real human-driven browsing session and audit
# the visited pages for WCAG 2.2 accessibility conformance.
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

"""Dutch (nl) translation catalog.

``MESSAGES`` maps English source strings to Dutch, merged from one
module per area (reports, checklist, checks, command line).
``CRITERION_NAMES`` holds the official Dutch WCAG 2.2 criterion titles.
WCAG terminology follows the W3C Authorized Translation of WCAG 2.2.
"""

from .checklist import MESSAGES as _CHECKLIST
from .checks import MESSAGES as _CHECKS
from .cli import MESSAGES as _CLI
from .criteria import CRITERION_NAMES
from .report import MESSAGES as _REPORT

MESSAGES: dict[str, str] = {**_REPORT, **_CHECKLIST, **_CHECKS, **_CLI}

__all__ = ["CRITERION_NAMES", "MESSAGES"]
