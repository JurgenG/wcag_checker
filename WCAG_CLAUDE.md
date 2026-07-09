# WCAG Automated Accessibility Testing — Build Guide (Python)

This file guides Claude Code in building reusable **libraries** for automated WCAG
accessibility testing against real, browser-loaded websites. It is meant to extend an
existing Python project referred to here as the **leak-detector** (a tool that loads
websites and inspects them for trackers). Treat this as the spec. Read it fully, then
**inspect the leak-detector before writing any code**.

## STEP 0 — Inspect the leak-detector first (do this before anything else)

Do not assume the stack. The leak-detector's own choices are authoritative — match them
so the new code feels native to the project, not bolted on. Determine:

1. **Browser driver.** Grep the codebase / dependency files for how it loads pages:
   - `selenium`, `webdriver`, `webdriver-manager` → Selenium
   - `playwright`, `sync_playwright`, `async_playwright` → Playwright (python)
   - `requests` + `beautifulsoup4` / `lxml` only, no browser → static HTTP (see warning below)
   - a mix → note which is used for the *page-loading* path specifically
   Check `pyproject.toml`, `requirements*.txt`, `setup.py`, `setup.cfg`, `Pipfile`, and
   actual imports. Imports win over declared deps if they disagree.

2. **Packaging.** Look for `pyproject.toml` (and whether it's Poetry / uv / hatch /
   setuptools), `setup.py`, or just loose scripts. Determine if it's a single package
   with submodules, a workspace/monorepo, or unpackaged scripts.

3. **Conventions.** Note: sync vs async, Python version floor, test framework (pytest?),
   linter/formatter (ruff/black/flake8), type-checking (mypy?), how config/secrets are
   handled, and the existing module layout.

**Report these findings back before generating the libraries**, then build to match. The
rest of this doc gives structure and WCAG logic that is driver-agnostic; slot in the
driver-specific parts based on what STEP 0 finds.

> ⚠️ **If the leak-detector is static-HTTP only (requests/BeautifulSoup, no real
> browser):** most WCAG automation needs a rendered DOM, computed styles, and focus
> behavior, which static HTML can't provide. Flag this to the user. The realistic paths
> are: (a) add a real browser driver (Playwright python recommended for greenfield) for
> the accessibility path while leaving the tracker path as-is, or (b) limit automated
> checks to the small subset detectable from raw HTML (presence of `alt`, `lang`,
> `<label>`, duplicate IDs) and send everything else to the manual checklist. Do not
> silently pretend full coverage is possible without a browser.

## Goal

Produce a small set of independent, composable modules/packages (not one monolithic
script) giving WCAG 2.2 AA coverage for what's automatable, and honestly surfacing what
isn't. Wrap the mature engine (**axe-core**, via its Python bindings) rather than
reimplementing static checks; spend custom code on the automatable gap axe doesn't
cover (keyboard/focus behavior).

Pick the axe binding that matches STEP 0's driver:
- Playwright python → `axe-playwright-python`
- Selenium → `axe-selenium-python` (or inject `axe.min.js` and call `axe.run()` directly)

## Why this shape (context — don't re-derive it)

WCAG 2.2 has 87 success criteria. Empirically: ~30% are fully automatable via DOM/static
analysis (axe-core covers this well), ~10% are partially automatable (tool flags a
candidate, human confirms), ~60% need human judgment (out of scope for assertions —
emit as a checklist). A few automatable criteria (contrast, `lang`, alt text,
name/role/value, bypass blocks, parsing, info/relationships) account for the large
majority of real-world issues by volume, so prioritize them in build order.

## Module structure

Mirror the leak-detector's packaging style (from STEP 0). If it's a single package with
submodules, add a subpackage like `wcag/` with the modules below. If it's a
workspace/monorepo, add sibling packages. Conceptual layout:

```
wcag/
├── core.py            # shared dataclasses + WCAG criteria registry (no driver dep)
├── axe_runner.py      # wraps axe-core binding, normalizes output
├── keyboard_nav.py    # focus/keyboard checks axe does NOT do (the custom value)
├── manual_checklist.py# generates human-review checklist for the ~60% + partials
└── reporter.py        # merges findings, outputs json / markdown / html + coverage note
```

Keep `core` free of any browser/driver import so it stays reusable.

### core.py
Dataclasses and the criteria registry, no driver dependency.
- `WcagCriterion`: `id: str`, `name: str`, `level: Literal['A','AA','AAA']`,
  `automatable: Literal['full','partial','manual']`
- `Finding`: `criterion: str`, `severity: Literal['error','warning','needs-review']`,
  `message: str`, `selector: str | None`, `url: str`
- `CRITERIA_REGISTRY`: the full WCAG 2.2 list with the `automatable` tier from the
  appendix, so downstream code and reports can label output without re-deriving coverage.

### axe_runner.py
Thin wrapper over the chosen axe binding.
- `run_axe_scan(page_or_driver, *, level='AA', tags=None, exclude=None) -> list[Finding]`
- Default AA tags: `['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']`.
- Normalize axe violations into `Finding`. Take the driver/page handle as-is from the
  caller — do not create or manage the browser session here; the leak-detector already
  owns page loading, reuse its session so a page is scanned in the same state the
  tracker analysis sees it.
- Any rule suppression needs an inline comment explaining the false-positive reasoning —
  never silence findings just to make a run green.

### keyboard_nav.py
The highest-value custom code — axe-core deliberately skips focus/keyboard flow. Each is
a standalone function returning `list[Finding]`:
- `check_focus_visible(...)` — for each focusable element, focus it and assert a visible
  indicator appears (compare computed outline/box-shadow before vs. after; flag if
  identical). Supports 2.4.7 / 2.4.11.
- `check_no_keyboard_trap(...)` — Tab forward (focusable_count + 1) times; confirm focus
  isn't stuck and doesn't escape the document unexpectedly. Supports 2.1.2.
- `check_tab_order(...)` — compare DOM focus order vs. visual (bounding-box) order, flag
  mismatches. Supports 2.4.3.
- `check_target_size(...)` — flag interactive elements under 24×24 CSS px without
  adequate spacing. Supports 2.5.8.
Implement the focus/tab mechanics using STEP 0's driver API (Playwright
`page.keyboard.press('Tab')` + `locator.evaluate`, or Selenium `ActionChains` +
`execute_script`).

### manual_checklist.py
Not a test runner — a checklist generator, because ~60% of WCAG can't be automated.
- Exports the manual-only criteria (link purpose in context, error-message quality,
  plain language, meaningful vs. merely-present alt text, cognitive load, etc.).
- Generates a markdown/JSON checklist per route, pre-filled with the URL and any
  `needs-review` (partial-tier) findings from the automated run.

### reporter.py
- Merge findings from `axe_runner` + `keyboard_nav`, grouped by WCAG criterion (not just
  rule id).
- Output JSON, Markdown, and a minimal HTML page.
- Always include a coverage summary stating how many criteria were actually exercised and
  that a clean run does **not** imply full WCAG conformance — manual review still
  required. Don't let green imply done.

## Example usage (adapt handle to STEP 0's driver)

```python
# Reusing the leak-detector's already-loaded page/driver for a given URL
from wcag.axe_runner import run_axe_scan
from wcag.keyboard_nav import (
    check_focus_visible, check_no_keyboard_trap, check_tab_order,
)
from wcag.reporter import write_report

def audit_page(page, url: str) -> list["Finding"]:
    findings = [
        *run_axe_scan(page, level="AA"),
        *check_focus_visible(page),
        *check_no_keyboard_trap(page),
        *check_tab_order(page),
    ]
    write_report(findings, route=url, out_dir="reports")
    return findings
```

If the leak-detector already iterates a list of URLs for tracker analysis, hook
`audit_page` into that same loop so both analyses run per page load.

## Milestones (build in order)

1. STEP 0 inspection + report findings back.
2. `core` dataclasses + criteria registry.
3. `axe_runner` — highest ROI (wraps existing tooling); get one real page scanning
   end-to-end before anything else.
4. `reporter` — minimal JSON first, so milestone 3 is usable immediately.
5. `keyboard_nav` — start with `check_focus_visible` and `check_no_keyboard_trap`
   (cheapest, highest value), then `check_tab_order`, then `check_target_size`.
6. `manual_checklist`.
7. Polish reporter (markdown/HTML), integrate into the leak-detector's URL loop.

## Non-goals / scope boundaries

- No screen-reader announcement testing (NVDA/JAWS/VoiceOver scripting) — mark manual.
- No content-quality heuristics (plain language, error helpfulness) — mark manual, don't
  ship a heuristic that only produces noise.
- No silent axe suppressions — every exclusion needs a justifying comment.

## Coding conventions

- Match the leak-detector's Python floor, formatter, linter, and sync/async style
  (STEP 0). Don't introduce a second formatter or a different async model.
- Type-hint public functions; every check returns `list[Finding]` and never raises for
  "issues found" — only for real execution errors (page crashed, selector failed).
- pytest each `keyboard_nav` check against a tiny local fixture HTML page with a
  known-good and known-bad variant, so correctness isn't only validated against live
  external sites.
- Document each check with the WCAG criterion id(s) it supports in the docstring.

## Appendix: automatability tiers (seed data for core's registry)

**Full** — 1.1.1, 1.3.1 (structural parts), 1.4.3, 1.4.6, 2.4.1, 3.1.1, 4.1.1, 4.1.2,
autocomplete validity, ARIA attribute validity, duplicate-ID checks.

**Partial** — 2.4.4 / 2.4.9 (link-text heuristics), 1.4.10, 1.4.12, 2.5.8, heading order.

**Manual** — 2.1.1, 2.1.2 (trap detection partially covered by keyboard_nav; full
keyboard operability still needs review), 2.4.3 / 2.4.7 (order partially covered,
semantic correctness manual), 1.3.3, 3.3.1–3.3.4, 3.1.5, all AAA content-quality criteria.
