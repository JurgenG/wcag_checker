# TODO

Task queue for `wcag-checker`, a WCAG 2.2 AA accessibility auditor forked
from the `leak_inspector` privacy tool. A clean automated run never
implies conformance.

## Done

### Foundations & conversion

- WCAG 2.2 criteria registry (`wcag/core.py`) — `WcagCriterion` +
  `Finding` dataclasses, each criterion tagged with an automatability
  tier (`full` / `partial` / `manual`). Driver-free single source of
  truth for coverage claims.
- Registry corrections for WCAG 2.2 fidelity — dropped 4.1.1, 2.4.7 → A,
  4.1.3 → manual.
- Removed the entire privacy pipeline (tracker `modules/`, `analysis/`,
  `enrichment/`, `dns_posture/`, `http_posture/`, `cms/`, privacy
  `report/`, top-level `cli.py`/`__main__.py`/`signals.py`/`impact.py`,
  `cname_provider.py`, `bulk-tool/` scanner) and repointed stale
  docstrings; kept `capture/`, `bundle/`, `events.py`, `safe_net.py` and
  `bulk-tool/datasets/`.
- Packaging pass (`pyproject.toml`) — distribution renamed to
  `wcag-checker`, `requires-python >=3.12`, added `axe-selenium-python`,
  dropped unused deps and the PDF/weasyprint group.
- Documentation — `README.md`, `CLAUDE.md`, `INSTALL.md`, `PROJECT.md`,
  `SBOM.md`, `docs/` rewritten for the new project.

### Automated checks

- axe-core wrapper (`wcag/axe_runner.py`) — runs the AA tag set, maps
  axe `wcag*` tags to dotted ids, normalizes violations + incomplete
  into `Finding`s, drops non-WCAG/best-practice results and criteria
  owned elsewhere.
- Keyboard/focus checks axe skips (`wcag/keyboard_nav.py`) — focus
  visibility (2.4.7 / 2.4.11), keyboard traps (2.1.2), tab order
  (2.4.3), target size (2.5.8, reconciled so only one engine reports it).
  Each check splits into an impure gatherer + pure evaluator.
- Media checks (`wcag/media.py`) — inventories native `<audio>`/`<video>`
  (stating the caption/subtitle/description `<track>`s found) for 1.2.1 /
  1.2.3, and flags un-auditable YouTube/Vimeo embeds (1.2.2 + 1.2.3) and
  other iframes (1.2.1); all `needs-review`, each with a screenshot.
- Manual-review pointers (`wcag/pointers.py`) — locates the concrete
  elements behind otherwise-manual criteria and points the reviewer at
  them (`needs-review`, with screenshots): 4.1.3 live regions, 3.3.8
  password fields + CAPTCHA, 2.4.5 search/nav/sitemap, 3.2.6 help/contact.
- Descriptive-text heuristics (`wcag/content.py`) — 2.4.4 generic link
  text and 2.4.6 empty headings, both `needs-review`.
- Reflow (`wcag/reflow.py`) — true 320 CSS-px viewport via BiDi,
  horizontal-overflow flag, operator viewport restored afterwards.

### Manual-review aids

- Manual checklist (`wcag/manual_checklist.py`) — selects in-scope
  manual/partial criteria, pairs them with audited routes, and renders
  concrete step-by-step review questions per criterion (Markdown + JSON),
  with a completeness test pinning questions to criteria.
- Reading view (`wcag/text_view.py`) — linearized accessible-name reading
  view of the live page, embedded in every report as a review aid (no
  pass/fail claim).
- Plaintext rendering — plaintext view included in reports to validate
  screen-reader performance (needs manual check).

### Reporting

- Reporter (`wcag/reporter.py`) — pure build-once/render-many: folds
  findings into a `ReportDocument` grouped by criterion + coverage
  summary; renders JSON (canonical), text, Markdown, HTML. Every format
  carries the coverage summary and the "clean run ≠ conformance"
  disclaimer.
- Priority-forward reports — `Finding.impact` carries axe severity;
  `Priority` bands (P1–P4) sort findings worst-first; scorecard +
  priority-overview table; `jira-tickets` format with band in
  title/priority/labels.
- `--format` selection.
- Per-finding screenshots (`wcag/screenshot.py`) — element-level PNG
  evidence with the flagged element boxed, deduped by `(url, selector)`,
  surfaced in every report format.

### Session, CLI & batch

- Session runner + `wcag-checker` CLI — live per-page audit on the BiDi
  audit hotkey (F9, polled so it survives CSP), findings accumulated in
  memory, all reports + `results.json` + `manual-checklist.md` written on
  window close.
- `--width` flag — audit alternate viewport widths (e.g. responsive
  views).
- Batch mode (`wcag-batch`) — audits a URL list (plain one-per-line or a
  two-column `name,website` CSV) reusing one Firefox, writing per-site
  reports + an aggregate summary; failing sites recorded and skipped;
  `--limit` caps large lists.

## TODO

- Native-speaker review of the Dutch translations by someone who knows
  Dutch accessibility terminology: the manual checklist
  (`i18n/nl/checklist.py`), the finding messages (`i18n/nl/checks.py`),
  the report labels (`i18n/nl/report.py`) and axe-core's messages
  (`wcag/locales/axe-nl.json`). Criterion titles are official (W3C) and
  need no review.