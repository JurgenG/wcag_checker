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

- [ ] `wcag/axe_runner.py` — wrap `axe-selenium-python`: inject axe-core,
      run with the AA tag set (`wcag2a`, `wcag2aa`, `wcag21a`,
      `wcag21aa`, `wcag22aa`), normalize violations + incomplete results
      into `Finding` objects. Take the driver as-is; never own the
      session. Any rule suppression needs a justifying inline comment.
      Hermetic tests against a canned axe results dict.
- [ ] `wcag/reporter.py` — merge findings grouped by WCAG criterion (not
      rule id); render JSON (canonical `results.json`) first, then text,
      Markdown, and a self-contained HTML page. Always emit a coverage
      summary stating which criteria were exercised and that a clean run
      is not conformance. Pure; hermetic tests.
- [ ] `wcag/keyboard_nav.py` — the focus/keyboard checks axe skips, each
      returning `list[Finding]`, each with a known-good and known-bad
      fixture:
  - [ ] `check_focus_visible` — 2.4.7 / 2.4.11
  - [ ] `check_no_keyboard_trap` — 2.1.2
  - [ ] `check_tab_order` — 2.4.3
  - [ ] `check_target_size` — 2.5.8
- [ ] `wcag/manual_checklist.py` — generate the human-review checklist
      for the manual-tier (and partial-tier `needs-review`) criteria,
      pre-filled per route with the URL. Not a test runner.
- [ ] Session runner + `wcag-checker` CLI — reuse the capture driver and
      the BiDi hotkey signal to run a live per-page audit on `Ctrl+Alt+A`;
      accumulate findings in memory; write reports + `results.json` to
      the output directory on window close.

## Final cleanup

- [ ] Remove the whole privacy pipeline: tracker `modules/`, `analysis/`,
      `enrichment/`, `dns_posture/`, `http_posture/`, `cms/`, the
      privacy-specific `report/` content, and their tests.
- [ ] `pyproject.toml`: add `axe-selenium-python`, raise
      `requires-python` to `>=3.12`, drop `tldextract` / `dnspython` /
      `maxminddb`, rename the console entry point to `wcag-checker`.
- [ ] Final README / SBOM pass once the tree reflects reality.

## Additional features
- [ ] Add step by step questions for a manual check of a page by a human