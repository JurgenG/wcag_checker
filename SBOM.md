# Software Bill of Materials

Tracks every third-party software dependency and data source the
`leak_inspector` codebase pulls in at build, install, or runtime.
Update this file whenever a dependency is added, removed, or
version-bumped.

## Runtime Python dependencies

Declared in `pyproject.toml`; installed by `pip install -e .`.

| Package    | Version pin | License      | Purpose |
|---         |---          |---           |--- |
| selenium   | >=4.20      | Apache-2.0   | WebDriver-BiDi browser-capture driver |
| tldextract | >=5.1       | BSD-3-Clause | Public Suffix List → eTLD+1 parsing |
| dnspython  | >=2.4       | ISC          | DNS-posture resolvers + DNSSEC checks |
| maxminddb  | >=2.5       | Apache-2.0   | GeoLite2 mmdb reader (geo enrichment) |
| pillow     | >=10        | MIT-CMU      | PNG → lossless-webp screenshot conversion for reports |

Transitive dependencies are not enumerated here; generate a complete
lock with `pip freeze` for release audits.

## Build dependencies

| Package    | Version pin | License | Purpose |
|---         |---          |---      |--- |
| setuptools | >=68        | MIT     | PEP 517 build backend |

## System dependencies (capture-side)

| Tool        | Source                | License                | Purpose |
|---          |---                    |---                     |--- |
| Firefox     | mozilla.org           | MPL-2.0                | Captured browser |
| geckodriver | mozilla.org           | MPL-2.0                | Selenium ↔ Firefox WebDriver-BiDi bridge |
| Python      | python.org / distro   | PSF License (BSD-style)| Runtime (>=3.10) |

## External services / data sources (analysis-side)

| Source                       | Access mode               | License / terms |
|---                           |---                        |--- |
| MaxMind GeoLite2-Country     | local mmdb file           | MaxMind GeoLite2 EULA — attribution required; **not redistributed by this project** (end-users download with their own license key via `leak-inspector update-geoip`) |
| Team Cymru IP→ASN mapping    | public DNS (no key)       | Free for any use per Team Cymru |
| Public Suffix List           | bundled with `tldextract` | MPL-2.0 |
| System DNS resolvers         | OS-configured             | n/a |

## Bundled assets

| Asset | Location | License | Purpose |
|---    |---       |---      |--- |
| BeLibre logo | `leak_inspector/report/assets/belibre_logo.svg` | © BeLibre, used with permission | Report branding (inlined as SVG) |
| Twemoji (Mozilla build) | `leak_inspector/report/assets/TwemojiMozilla.ttf` | **CC-BY 4.0** — attribution: Twemoji © Twitter, Inc and contributors | Colour-emoji source for PDF export. Read with `fontTools` (already a WeasyPrint dep) to convert glyphs to inline SVG; not registered as a text font. WeasyPrint can't colour-render emoji glyphs inline at body size, so emoji are emitted as SVG instead. |

## License posture

- This project: **GPL-3.0-or-later** (see `LICENSE`).
- Bundled Twemoji graphics are CC-BY 4.0 — a non-functional data asset,
  GPL-compatible with attribution (recorded above).
- All declared deps are permissively licensed (Apache / BSD / ISC /
  MIT / MPL) and compatible with GPL-3.0-or-later distribution.
- Capture bundles produced by the tool contain *user-supplied
  browsing content* and are not subject to the codebase's license.

## Key processes

### Adding a new Python dependency

1. Declare it in `pyproject.toml` under `[project].dependencies`
   with a `>=` lower bound.
2. Add a row in the *Runtime Python dependencies* table above
   (package, pin, license, one-line purpose).
3. Verify the license is compatible with GPL-3.0-or-later
   distribution (Apache-2.0 / BSD / ISC / MIT / MPL-2.0 are safe).
4. If the dep ships its own data files (mmdb / certificate bundles
   / etc.), record the data source under *External services / data
   sources* and add a refresh process below.

### Removing or version-bumping a dependency

1. Update the pin in `pyproject.toml`.
2. Update this file's table.
3. Verify nothing else still imports the removed module
   (`grep -r 'import <name>' leak_inspector/`).

### Refreshing the GeoLite2 mmdb

The MaxMind GeoLite2 license requires the database be kept
reasonably current (weekly upstream updates). End-user refresh:

```
export MAXMIND_LICENSE_KEY=...
leak-inspector update-geoip
```

There is **no automated freshness check** at analysis time; stale
data silently returns older country attributions. The mmdb is
cached at `~/.cache/leak_inspector/GeoLite2-Country.mmdb`
(override via `$LEAK_INSPECTOR_GEOIP_DB`).

### Verifying the analysis-time DNS surface

The DNS-posture analyser issues live lookups against the bundle's
`base_domain` at analysis time. To verify behaviour without network:

- Skip the lookup entirely by calling `analyze_events()` directly
  rather than `analyze_bundle()` (the former does not perform
  network I/O; the latter does).
- Provide a captive resolver via `dnspython`'s standard
  configuration channels (`/etc/resolv.conf` or environment
  variables honoured by `dns.resolver.Resolver`).

### Versioning the enrichment artifact

The stored `enrichment.json` carries its own `ENRICHMENT_VERSION`
(`leak_inspector/enrichment/artifact.py`), independent of the bundle
schema. Reads are tolerant: unknown keys are ignored and missing
fields take their defaults, so an older reader survives a newer writer
and vice-versa. Bump the version when the contract changes and keep
new fields optional with safe defaults.

- **v1** — DNS / transport / CMS / security.txt / per-host IP posture
  under a single `enriched_at` timestamp.
- **v2** — added `section_timestamps` (per-section last-probe times,
  keyed by canonical section id) so a selective
  `enrich --refresh <section>` can re-probe one section without
  misstating the age of the others. v1 artifacts read fine and carry
  an empty map; readers fall back to `enriched_at`.
