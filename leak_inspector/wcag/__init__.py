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

"""WCAG 2.2 accessibility auditing.

Composable, single-responsibility modules that audit a live,
browser-rendered page for WCAG 2.2 AA conformance and honestly surface
what cannot be automated:

* :mod:`.core` — driver-free dataclasses and the WCAG 2.2 criteria
  registry (the one place that says which criteria are automatable).
* :mod:`.axe_runner` — wraps the axe-core engine (via
  ``axe-selenium-python``) and normalizes its output into
  :class:`~.core.Finding` objects.
* :mod:`.keyboard_nav` — focus / keyboard-flow checks that axe-core
  deliberately does not perform.
* :mod:`.manual_checklist` — generates the human-review checklist for
  the majority of criteria that cannot be asserted automatically.
* :mod:`.reporter` — merges findings by criterion and renders JSON /
  text / Markdown / HTML with an explicit coverage summary.
"""