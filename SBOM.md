# Software Bill of Materials

Tracks every third-party software dependency and data source the
`wcag-checker` codebase pulls in at build, install, or runtime. Update
this file whenever a dependency is added, removed, or version-bumped.

## Runtime Python dependencies

Declared in `pyproject.toml`; installed by `pip install -e .`.

| Package              | Version pin | License    | Purpose |
|---                   |---          |---         |--- |
| selenium             | >=4.20      | Apache-2.0 | WebDriver-BiDi browser-capture driver |
| axe-selenium-python  | >=3.0       | MPL-2.0    | Wraps the axe-core accessibility engine (bundles axe-core 4.10.2, MPL-2.0) and injects it into the page |
| pillow               | >=10        | MIT-CMU    | PNG → lossless-webp screenshot conversion for reports |

Transitive dependencies are not enumerated here; generate a complete
lock with `pip freeze` for release audits.

## Build dependencies

| Package    | Version pin | License | Purpose |
|---         |---          |---      |--- |
| setuptools | >=68        | MIT     | PEP 517 build backend |

## System dependencies (capture-side)

| Tool        | Source              | License                 | Purpose |
|---          |---                  |---                      |--- |
| Firefox     | mozilla.org         | MPL-2.0                 | Captured browser |
| geckodriver | mozilla.org         | MPL-2.0                 | Selenium ↔ Firefox WebDriver-BiDi bridge (auto-provisioned by Selenium Manager) |
| Python      | python.org / distro | PSF License (BSD-style) | Runtime (>=3.12) |

## Bundled data / rulesets

| Asset | Location | License | Purpose |
|---    |---       |---      |--- |
| axe-core ruleset | ships inside `axe-selenium-python` | MPL-2.0 (axe-core 4.10.2) | The accessibility rules the tool runs. Injected into the live page and executed via `axe.run()`; the tool does not vendor its own copy. |

The fork's `report/assets` (BeLibre logo, Twemoji font used for PDF
export) are being removed: the WCAG HTML report is self-contained with
inline CSS and needs no external font or logo assets.

## License posture

- This project: **GPL-3.0-or-later** (see `LICENSE`).
- `axe-selenium-python` and the bundled axe-core engine are **MPL-2.0**,
  which is GPL-3.0-or-later-compatible.
- `selenium` (Apache-2.0) and `pillow` (MIT-CMU) are permissively
  licensed and compatible with GPL-3.0-or-later distribution.
- Reports produced by the tool contain *user-supplied browsing content*
  and are not subject to the codebase's license.

## Key processes

### Adding a new Python dependency

1. Declare it in `pyproject.toml` under `[project].dependencies`
   with a `>=` lower bound.
2. Add a row in the *Runtime Python dependencies* table above
   (package, pin, license, one-line purpose).
3. Verify the license is compatible with GPL-3.0-or-later
   distribution (Apache-2.0 / BSD / ISC / MIT / MPL-2.0 are safe).
4. If the dep ships its own data files (rulesets / fonts / etc.),
   record them under *Bundled data / rulesets*.

### Removing or version-bumping a dependency

1. Update the pin in `pyproject.toml`.
2. Update this file's table.
3. Verify nothing else still imports the removed module
   (`grep -r 'import <name>' leak_inspector/`).

### Updating the bundled axe-core version

The accessibility engine is not vendored directly — it rides inside
`axe-selenium-python`. To move to a newer axe-core:

1. Bump the `axe-selenium-python` pin in `pyproject.toml` and reinstall.
2. The effective axe-core version is whatever that release bundles
   (currently **4.10.2**). Confirm it in the installed package:
   `node_modules/axe-core/package.json` under the package directory.
3. After a bump, verify the WCAG tag set the runner requests
   (`wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22aa`) is still
   supported — WCAG 2.2 tags require axe-core >= 4.8. A regression test
   should fail loudly if a tag disappears.