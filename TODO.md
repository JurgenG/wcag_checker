# TODO

Task queue for converting the `leak_inspector` privacy-tool fork into
`wcag-checker`, a WCAG 2.2 AA accessibility auditor. Built in milestone
order; a clean automated run never implies conformance.

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
- [ ] `wcag/manual_checklist.py` — generate the human-review checklist
      for the manual-tier (and partial-tier `needs-review`) criteria,
      pre-filled per route with the URL. Not a test runner.
- [ ] Session runner + `wcag-checker` CLI — reuse the capture driver and
      the BiDi hotkey signal to run a live per-page audit on `Ctrl+Alt+A`;
      accumulate findings in memory; write reports + `results.json` to
      the output directory on window close.

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
      `capture/recorder.py` + `capture/dns.py`), remove the dangling
      `leak-inspector = leak_inspector.cli:main` entry point and the
      `report/assets` package-data, rename the console entry point to
      `wcag-checker`.
- [ ] Final README / SBOM pass once the tree reflects reality.

## Additional features
- [ ] Add step by step questions for a manual check of a page by a human