# wcag-checker

`wcag-checker` audits web pages for **WCAG 2.2 AA** accessibility. It opens a real Firefox window, you browse the site as a visitor would, and on any page you want checked you press **F9**. The tool audits that page exactly as it is on screen — after cookie banners, menus, logins and client-side rendering — and when you close the window it writes a report.

Reports, checklists and terminal messages are in **Dutch** by default; add `--lang en` for English.

Each report combines automated findings, screenshots of every flagged element, a coverage table for all WCAG 2.2 A + AA criteria, and a step-by-step checklist for the criteria a person has to judge. Together they form the starting point of a full accessibility review.

## Install

[INSTALL.md](INSTALL.md) walks through the installation on Windows, macOS and Linux, starting from a computer with nothing installed.

Requirements: Python 3.12 or newer, Git, Firefox, and a desktop session with a visible screen.

## Usage

There are three ways to run it. All of them write the same kind of report.

### Interactive: browse and press F9

```bash
wcag-checker https://example.com
```

1. Firefox opens on the URL. Browse the site normally.
2. On a page you want checked, click once inside the page, then press `F9`. The terminal confirms each audit, e.g. `geauditeerd: https://example.com/ — 12 bevinding(en)`. Repeat on as many pages as you like.
3. Close the Firefox window. The reports are written and the terminal lists the files.

### One page, automatically: `--once`

```bash
wcag-checker https://example.com --once
```

Opens Firefox, waits for the page to finish loading (following any redirect), audits it, writes the report and closes.

### A list of sites: `wcag-batch`

```bash
wcag-batch urls.txt
wcag-batch bulk-tool/datasets/publiq/domains.csv --limit 20
```

Audits every URL in a file, one after the other, in one Firefox window. The file contains either one URL per line, or two comma-separated columns such as `name,website` (the name then labels the site in the summary). Lines starting with `#` and blank lines are skipped. A site that cannot be reached is recorded as failed and the run continues. Example lists are in `bulk-tool/datasets/`.

### Options

| Option | Applies to | Effect |
| --- | --- | --- |
| `--out DIR` | all | Where reports go. Default `reports/` (`runs/` for `wcag-batch`). |
| `--lang LANG` | all | Language of the reports, checklist and terminal messages: `nl` (default) or `en`. |
| `--format FMT` | all | Report format(s), comma-separated. Default `html`. See [Output](#output). |
| `--width PX` | all | Resize the window to this width before auditing, to check a mobile layout, e.g. `--width 375`. Firefox has a minimum window width of about 500 px; the tool warns when it audited at a wider width than asked. |
| `--headless` | all | Run Firefox without a visible window. Keyboard and focus checks are most reliable with a visible window. |
| `--hotkey COMBO` | interactive | Use a different audit key, e.g. `--hotkey ctrl+alt+shift+a`. Modifiers: `ctrl`, `alt`, `shift`, `meta`. |
| `--once` | `wcag-checker` | Audit the starting page once and exit. |
| `--limit N` | `wcag-batch` | Audit only the first N URLs. |

## What gets checked

Every audit runs these checks against the live page and groups the results by WCAG success criterion:

- **axe-core** with the WCAG 2.0 / 2.1 / 2.2 A and AA rules: colour contrast, page language, names/roles/values, ARIA validity, captions on native video (1.2.2), autoplaying audio (1.4.2), meta refresh (2.2.1), moving content (2.2.2), label in name (2.5.3), and more.
- **Keyboard and focus**: visible focus indicator and focus not hidden (2.4.7 / 2.4.11), keyboard traps (2.1.2), positive `tabindex` overriding focus order (2.4.3), targets smaller than 24×24 px (2.5.8).
- **Media**: native `<audio>` (1.2.1 transcript) and `<video>` (1.2.3 audio description), listing the caption/subtitle/description tracks found; YouTube and Vimeo embeds (1.2.2 + 1.2.3); other embedded frames (1.2.1).
- **Review pointers** for criteria a person must judge, pointing at the exact elements to look at: live regions (4.1.3), password fields and CAPTCHAs (3.3.8), search / navigation / sitemap (2.4.5), help and contact links (3.2.6).
- **Descriptive text**: generic link text such as "click here" or "read more" (2.4.4), empty headings (2.4.6).
- **Reflow**: horizontal scrolling at a 320 px wide viewport (1.4.10).

Every report also contains a **reading view**: the page's content and accessible names in source order, roughly the way a screen reader or text-only browser reads it, with unnamed elements marked. It helps a reviewer judge reading order and naming.

## Languages

`--lang` sets the language of everything the tool writes: the reports, the JIRA tickets, the manual checklist, the batch summary, `--help` and the terminal messages.

- **Criterion names** use the official titles from the W3C [Authorized Dutch Translation of WCAG 2.2](https://www.w3.org/Translations/WCAG22-nl/).
- **axe-core messages** (rule titles and the per-element "Los een van de volgende problemen op" details) come from a Dutch translation of axe-core's messages that ships with the tool.
- **Machine-readable values** stay the same in every language: in `results.json` and `summary.json` the ids, severities, tiers and statuses are always `error`, `needs-review`, `full`, … and a `lang` field records the report language.
- JIRA ticket filenames use the English criterion name, so they stay the same across languages.

## Output

`wcag-checker` writes into a folder per website inside `--out`, e.g. `reports/example.com/`. Every filename starts with the date and time of the run (`202611041530_report.html`), so repeated audits of the same site sit side by side.

`--format` chooses the report formats (comma-separated, e.g. `--format html,jira-tickets`):

| `--format` | File | Contents |
| --- | --- | --- |
| `html` *(default)* | `report.html` | Findings by criterion with screenshot thumbnails, the coverage table, the reading view and the manual checklist. Opens in any browser; works offline. |
| `md` | `report.md` | The same as Markdown. |
| `txt` | `report.txt` | The same as plain text. |
| `json` | `results.json` | Machine-readable: every finding (criterion, severity, message, selector, screenshot path), the coverage table and the reading view. |
| `jira-tickets` | `jira/*.md` | One JIRA-style ticket per WCAG criterion with affected elements and acceptance criteria. |
| `all` | all of the above | |

Always written:

| File | Contents |
| --- | --- |
| `manual-checklist.md` | Step-by-step review questions for the 46 A + AA criteria that need human judgement, for every audited page. |
| `screenshots/` | One PNG per flagged element, with the element outlined. |

`wcag-batch` writes one folder per site (`runs/<site>/report.html`, …) plus `runs/summary.html`, `summary.md` and `summary.json` with one row per site linking to its report.

### Reading the results

Each finding has a **severity**:

- **error** — a definite failure.
- **warning** — a lower-impact definite failure.
- **needs-review** — a candidate a person confirms or dismisses.

axe-core's own grading (`critical`, `serious`, `moderate`, `minor`) is kept as the finding's **impact**.

Reports open with a **priority overview** and list criteria worst-first:

| Band | Meaning |
| --- | --- |
| **P1 · Critical** | Definite failure of a level A criterion. |
| **P2 · High** | Definite failure of a level AA criterion. |
| **P3 · Medium** | Lower-impact definite failure (warning). |
| **P4 · Review** | Only candidates; a person triages them first. |

Within a band, criteria are ordered by impact, then by number of occurrences. JIRA tickets carry the band in their title, priority field and labels.

## Coverage

Every WCAG 2.2 success criterion has a coverage tier:

- **full** — the tool decides the automatable part (e.g. colour contrast, page language, name/role/value).
- **partial** — the tool flags candidates and a person confirms (e.g. link text, reflow, focus order, target size).
- **manual** — a person decides, guided by the checklist and any review pointers (e.g. whether alt text is meaningful, error-message quality).

Of the 55 level A + AA criteria, 9 are full, 22 partial and 24 manual. The coverage table in each report shows, per criterion, the number of findings, *no automated finding*, or *needs manual review*. A WCAG 2.2 AA conformance claim combines the automated findings with the completed manual checklist. See [docs/COVERAGE.md](docs/COVERAGE.md) for the full breakdown.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
