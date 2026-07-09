# TODO

Task queue for converting the `leak_inspector` privacy-tool fork into
`wcag-checker`, a WCAG 2.2 AA accessibility auditor. Built in milestone
order; a clean automated run never implies conformance.

## Session state — resume here (last worked 2026-07-09)

- **Branch:** `feature/screenshots` (branched off `main` after
  `feature/session-runner` was fast-forward merged). Branch-style
  development — start each new step on its own branch off `main`.
- **Uncommitted on this branch, ready to commit:**
  - `leak_inspector/wcag/screenshot.py` (new) — element-evidence gatherer
  - `leak_inspector/wcag/core.py` — `Finding.screenshot` field added
  - `leak_inspector/session.py` — `audit_page` captures evidence into
    `<out>/screenshots/`; `SCREENSHOT_DIRNAME` constant
  - `leak_inspector/wcag/reporter.py` — evidence in JSON/text/md/HTML
  - `tools/wcag_smoke.py` — capture wired into `--out`; stale docstring
    fixed
  - `tests/test_wcag_screenshot.py` (new) + `tests/test_wcag_session.py`
    (`audit_page` wiring)
  - `README.md`, `TODO.md` (this file)
- **Tests:** full suite green — **369 passing**. Run with
  `. .venv/bin/activate && python -m pytest -q`.
- **Verified live:** `tools/wcag_smoke.py https://www.publiq.be --out …`
  produced 86 findings, all with an element PNG (84 distinct after
  dedup), and every `report.html` thumbnail link resolves.
- **Next build step:** the packaging pass (see Final cleanup) — declare
  `axe-selenium-python`, raise `requires-python`, drop stale deps /
  `report/assets` package-data.
- **Env note:** venv at `.venv`; the audit engine still needs
  `pip install axe-selenium-python` (not a declared dep yet — see Final
  cleanup).

## Done

- [x] STEP-0 inspection of the fork (driver, packaging, conventions,
      the reusable hotkey/screenshot mechanism, the report shape).
- [x] `git init` + baseline commit of the untouched fork, then a
      `wcag-conversion` working branch (deletions are recoverable).
- [x] `wcag/core.py` — `WcagCriterion` + `Finding` dataclasses and the
      full 87-criterion WCAG 2.2 registry, each tagged with an
      automatability tier (`full` / `partial` / `manual`). Driver-free.
- [x] `tests/test_wcag_core.py` — pins the registry (count, unique ids,
      valid levels/tiers, seed-tier anchors, honest tier distribution).
- [x] Documentation rewrite for the new project: `README.md`,
      `CLAUDE.md`, `INSTALL.md`, `PROJECT.md`, `SBOM.md`, `TODO.md`,
      `docs/`.

## Build queue

- [x] `wcag/axe_runner.py` — wraps `axe-selenium-python`: injects
      axe-core, runs the AA tag set (`wcag2a`, `wcag2aa`, `wcag21a`,
      `wcag21aa`, `wcag22aa`), normalizes violations + incomplete results
      into `Finding` objects via the criteria registry (axe `wcag*` tags
      → dotted ids). Takes the driver as-is; never owns the session.
      Non-WCAG (best-practice) results are dropped, not mislabelled.
      Hermetic tests in `tests/test_wcag_axe_runner.py`.
- [x] `tools/wcag_smoke.py` — throwaway runner (launch Firefox →
      navigate → axe audit → print by criterion) to exercise
      `axe_runner` on a live page before the session runner exists.
      Remove once the CLI lands.
- [x] `wcag/reporter.py` — pure build-once/render-many: `build_report`
      folds findings into a `ReportDocument` (grouped by criterion +
      registry-derived `CoverageSummary`); `render_json` (canonical
      `results.json`), `render_text`, `render_markdown`, `render_html`
      (self-contained, escaped) render it. Every format carries the
      coverage summary + the "clean run ≠ conformance" disclaimer; no
      criterion is ever reported as a pass. Hermetic tests in
      `tests/test_wcag_reporter.py`. Wired into `tools/wcag_smoke.py`
      (`--out` writes all four formats).
- [x] `wcag/keyboard_nav.py` — the focus/keyboard checks axe skips. Each
      splits into an impure gatherer (`check_*`, drives the live driver)
      and a pure evaluator (`evaluate_*`, canned data → `list[Finding]`);
      all emit `needs-review` candidates (partial-tier), never a pass.
      Hermetic good/bad fixtures in `tests/test_wcag_keyboard_nav.py`;
      gatherers live-smoked on publiq.be. Wired into `run_all` +
      `tools/wcag_smoke.py`.
  - [x] `check_focus_visible` — 2.4.7 / 2.4.11 (style diff on focus +
        elementFromPoint obscuring)
  - [x] `check_no_keyboard_trap` — 2.1.2 (Tab-press sequence, stuck-run
        detection)
  - [x] `check_tab_order` — 2.4.3 (positive-tabindex detection)
  - [x] `check_target_size` — 2.5.8 (24×24 CSS-px minimum, inline
        exception)
  - [ ] Reconcile 2.5.8 with axe: axe-core also tags a `target-size`
        rule `wcag22aa`, so this check may double-report under 2.5.8.
        Decide which owns it (or dedupe in the reporter).
- [x] `wcag/manual_checklist.py` — pure build-once/render-many:
      `build_checklist` selects the in-scope manual + partial criteria (46
      = 27 manual + 19 partial) and pairs them with the audited routes;
      `render_markdown` (`manual-checklist.md`, checkboxes grouped per
      page by tier) and `render_json` render it. Not a test runner — emits
      review tasks, never pass/fail. Hermetic tests in
      `tests/test_wcag_manual_checklist.py`; wired into
      `tools/wcag_smoke.py --out`.
- [x] Session runner + `wcag-checker` CLI — `leak_inspector/session.py`
      reuses the capture driver + the new BiDi `Ctrl+Alt+A` audit hotkey
      (`capture/bidi.py`) to run a live per-page audit on each keypress,
      accumulating findings in memory and writing all reports +
      `results.json` + `manual-checklist.md` on window close.
      `leak_inspector/cli.py` is the `wcag-checker` console entry point.
      The hotkey callback only enqueues; all WebDriver calls run on the
      main thread. Hermetic tests for the audit loop (fake driver) and
      the report-writing seam (tmp_path) + CLI wiring in
      `tests/test_wcag_session.py`; full chain live-smoked.
  - [x] Per-finding screenshots — `wcag/screenshot.py` captures an
        element-level PNG (the snippet with the issue) for each finding
        that has a selector, into `<out>/screenshots/`, deduping by
        `(url, selector)` so an element failing several criteria is shot
        once. `Finding.screenshot` carries the report-relative path; the
        reporter surfaces it (evidence field in JSON, thumbnail column in
        HTML, links in text/Markdown). Captured live in `audit_page`
        right after the audits, before navigation. Hermetic tests
        (`tests/test_wcag_screenshot.py`) with a fake driver + the
        `audit_page` wiring in `tests/test_wcag_session.py`; live-smoked
        on publiq.be (86 findings, 84 PNGs, all HTML links resolve).
        Wired into `tools/wcag_smoke.py --out` too.

## Final cleanup

- [x] Remove the whole privacy pipeline: tracker `modules/`,
      `analysis/`, `enrichment/`, `dns_posture/`, `http_posture/`,
      `cms/`, the privacy `report/` content, top-level `cli.py`,
      `__main__.py`, `signals.py`, `impact.py`, `cname_provider.py`, and
      their ~226 tests (kept `capture/`, `bundle/`, `events.py`,
      `safe_net.py`, `wcag/` and their tests — 305 tests still green).
- [ ] Privacy-removal loose ends still open:
  - `bundle/reader.py` — the `enrichment()` property lazily imports the
    now-deleted `..enrichment.artifact`; dead code, remove the property.
  - stale docstrings naming deleted modules (`safe_net.py`,
    `bundle/__init__.py`).
  - `bulk-tool/` — the privacy bulk scanner (imports `analysis`,
    `report`, …); now broken. Decide keep-and-port vs delete; its
    `datasets/` domain lists may be reusable for WCAG bulk auditing.
- [ ] `pyproject.toml`: add `axe-selenium-python`, raise
      `requires-python` to `>=3.12`, drop `maxminddb` (unused after
      removal) and reassess `tldextract` / `dnspython` (still imported by
      `capture/recorder.py` + `capture/dns.py`), and remove the
      `report/assets` package-data (that dir is gone). Done already: the
      console entry point is now `wcag-checker = leak_inspector.cli:main`.
- [ ] Final README / SBOM pass once the tree reflects reality.

## Additional features
- [ ] Add step by step questions for a manual check of a page by a human