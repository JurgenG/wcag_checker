# TODO

Task queue for converting the `leak_inspector` privacy-tool fork into
`wcag-checker`, a WCAG 2.2 AA accessibility auditor. Built in milestone
order; a clean automated run never implies conformance.

## Session state — resume here (last worked 2026-07-09)

- **Branch:** `feature/report-format` (off `main`). Hotkey is fixed and
  merged (polled `capture/hotkey.py`, default `f9`, CSP-immune; user
  confirmed F9 works). This branch adds report-format selection.
- **`--format` (this branch):** `write_reports(..., formats=...)` writes
  only the chosen findings report(s) instead of all of them; default
  `html`. `session.parse_formats` compiles a comma-separated spec into
  format names; `FORMAT_CHOICES` = `html, md, txt, json, jira-tickets,
  all`. `--format` added to `wcag-checker` and `wcag-batch` (per site),
  validated before launch. The manual-review checklist + screenshots are
  always written (not gated).
- **`jira-tickets` format:** `reporter.render_jira_tickets(document)`
  (pure) returns one JIRA-style Markdown ticket per WCAG criterion with
  findings; `write_reports` writes them into a `jira/` subfolder of the
  output dir. Verified live on publiq.be (79 findings → 4 tickets).
- **Tests:** full suite green — **173 passing** (`TestParseFormats`,
  format/jira cases in `test_wcag_session.py`, batch format pass-through).
- **Next build step:** nothing queued.
- **Env note:** venv at `.venv`; runtime deps are `selenium` +
  `axe-selenium-python` (`pip install -e .` pulls them in).

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
- [x] `tools/audit_page.py` — throwaway runner (launch Firefox →
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
      `tests/test_wcag_reporter.py`. Wired into `tools/audit_page.py`
      (`--out` writes all four formats).
- [x] `wcag/keyboard_nav.py` — the focus/keyboard checks axe skips. Each
      splits into an impure gatherer (`check_*`, drives the live driver)
      and a pure evaluator (`evaluate_*`, canned data → `list[Finding]`);
      all emit `needs-review` candidates (partial-tier), never a pass.
      Hermetic good/bad fixtures in `tests/test_wcag_keyboard_nav.py`;
      gatherers live-smoked on publiq.be. Wired into `run_all` +
      `tools/audit_page.py`.
  - [x] `check_focus_visible` — 2.4.7 / 2.4.11 (style diff on focus +
        elementFromPoint obscuring)
  - [x] `check_no_keyboard_trap` — 2.1.2 (Tab-press sequence, stuck-run
        detection)
  - [x] `check_tab_order` — 2.4.3 (positive-tabindex detection)
  - [x] `check_target_size` — 2.5.8 (24×24 CSS-px minimum, inline
        exception)
  - [x] Reconcile 2.5.8 with axe — `keyboard_nav` owns 2.5.8; `axe_runner`
        now drops any axe result mapping to it
        (`_CRITERIA_OWNED_ELSEWHERE`), so it can be reported by only one
        engine. Verified axe-core 4.10.2 ships `target-size` disabled by
        default (tags `wcag22aa`/`wcag258`), so the collision was latent;
        the drop is engine-agnostic and holds if a future axe enables it.
        Tests in `tests/test_wcag_axe_runner.py`.
- [x] `wcag/manual_checklist.py` — pure build-once/render-many:
      `build_checklist` selects the in-scope manual + partial criteria (46
      = 27 manual + 19 partial) and pairs them with the audited routes;
      `render_markdown` (`manual-checklist.md`, checkboxes grouped per
      page by tier) and `render_json` render it. Not a test runner — emits
      review tasks, never pass/fail. Hermetic tests in
      `tests/test_wcag_manual_checklist.py`; wired into
      `tools/audit_page.py --out`.
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
        Wired into `tools/audit_page.py --out` too.

## Final cleanup

- [x] Remove the whole privacy pipeline: tracker `modules/`,
      `analysis/`, `enrichment/`, `dns_posture/`, `http_posture/`,
      `cms/`, the privacy `report/` content, top-level `cli.py`,
      `__main__.py`, `signals.py`, `impact.py`, `cname_provider.py`, and
      their ~226 tests (kept `capture/`, `bundle/`, `events.py`,
      `safe_net.py`, `wcag/` and their tests — 305 tests still green).
- [x] Privacy-removal loose ends:
  - `bundle/reader.py` — removed the dead `enrichment()` property (it
    imported the deleted `..enrichment.artifact`) and its now-orphaned
    `_MAX_ENRICHMENT_BYTES` cap. No callers/tests.
  - stale docstrings repointed off deleted modules: `bundle/__init__.py`
    (dropped the `analysis` reference), `safe_net.py` (was documented
    against the deleted `cms`/`http_posture` probes; now describes its
    real consumer, `capture/page_source.py`), and one now-false
    "used by the bulk-tool runner" line in `capture/recorder.py`.
  - `bulk-tool/` — deleted the broken privacy scanner code
    (`run.py`, `overview.py`, `make_score_scatter.py`,
    `rerender_overview.py`); **kept** `bulk-tool/datasets/` (domain-list
    CSVs) for a possible future WCAG bulk-audit mode.
- [x] `pyproject.toml` packaging pass: added `axe-selenium-python>=3.0`,
      raised `requires-python` to `>=3.12` (dropped the 3.10/3.11
      classifiers), dropped `maxminddb` and `pillow` (imported nowhere)
      and the `pdf`/`weasyprint` optional group, removed the stale
      `report/assets` package-data. Renamed the distribution to
      `wcag-checker` (import package dir stays `leak_inspector/`) and
      rewrote the description/keywords/classifiers for WCAG. `tldextract`
      / `dnspython` are **kept** — `capture/recorder.py` (+ `capture/dns.py`)
      still use them and are exercised by `tests/test_capture_*`. README +
      INSTALL install steps and SBOM.md dependency table updated to match.
- [x] Final README / SBOM pass — README reframed off "mid-build" (every
      part now works), report-contents intro corrected, and the roadmap
      updated (core complete; only a possible `bulk-tool/` batch-audit
      mode noted). SBOM was already current from the packaging pass
      (verified: no stale pillow/weasyprint/maxminddb/PDF references).

## Additional features
- [x] Step-by-step questions for a human manual check of a page —
      `wcag/manual_checklist.py` now carries a `QUESTIONS` map (ordered,
      concrete review questions per in-scope manual/partial criterion,
      with applicability gates). `render_markdown` renders each criterion
      as a heading with its questions as checkboxes, per page;
      `render_json` adds a `questions` array. A completeness test pins
      that the question set exactly matches the review criteria (no gaps,
      no drift). Tests in `tests/test_wcag_manual_checklist.py`.
- [x] Batch-audit mode (`wcag-batch`) — `leak_inspector/batch.py` +
      `cli_batch.py` audit a plain-text URL list (one per line), reusing
      one Firefox and running the `--once` flow per site into
      `<out>/<site>/` (full report set + screenshots). A failing site is
      recorded (single-line error) and the run continues; an aggregate
      `summary.{json,md,html}` gives one row per site (findings by
      severity or failure) linking to each per-site report. `--limit`
      caps large lists; visible by default (`--headless` to hide). Reads
      the `bulk-tool/datasets/*/domains.csv` example lists. Hermetic tests
      in `tests/test_batch.py`; live-smoked on the `tinyset` dataset
      (2 audited, 1 DNS-failure recorded).