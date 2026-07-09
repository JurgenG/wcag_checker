# Test fixture bundles

Real capture bundles, frozen and committed for test ownership.
Originally copied from `captures/` and `bulk-tool/datasets/*/captures/`
but **owned by the test suite from this point on** — the originals
are working datasets that may be regenerated, edited, or deleted at
any time; these copies must not change underneath the tests.

## What each bundle represents

| File | Source site | What the tests exercise |
|---|---|---|
| `brecht.zip` | `www.brecht.be` (Belgian municipality, Drupal) | Verdict-layer zero-PII case (gov_flanders widget + Google Fonts only). Also a real Drupal CMS detection. |
| `cultuurkuur.zip` | `cultuurkuur.be` (cultural-sector portal) | Verdict-layer non-zero-PII case (GA4, Hotjar, Meta Pixel, Google Ads/DoubleClick, etc.). Transport-posture integration. |
| `aalst.zip` | `aalst.be` (Belgian municipality, Drupal) | CMS analyse-bundle integration test with the version probe. |
| `nbb.zip` | `nbb.be` (National Bank of Belgium) | Small bundle (7 KB) used by the CLI screenshot-embedding test. |
| `kbc.zip` | `kbc.com` (Belgian bank) | TrustArc CMP module test fixture. |
| `doccle-reject.zip` | `doccle.be` — consent rejected | A-side of the diff integration test (consent off: baseline trackers + reCAPTCHA + fonts). |
| `doccle-accept.zip` | `doccle.be` — consent accepted | B-side of the diff integration test (consent on: adds Facebook Pixel, AppNexus, Plausible, Sentry, Adobe Fonts). |
| `hindustantimes.zip` | `hindustantimes.com` (Indian news site) | Deliberately-foreign fixture: ad-tech-saturated, with stable unclassified hosts (e.g. `analytics.htmedia.in` → Akamai) that will never warrant an EU-public-sector module — anchors the `UnclassifiedHost.cdn_provider` CNAME-wiring test. Larger (~2.3 MB) than the rest, accepted by design for a permanently-unclassified host. |

## Adding a new fixture bundle

1. Identify the smallest real capture that exercises the behaviour
   you need (the test suite already runs against ~3 MB total — keep
   that small).
2. Copy the zip into this directory under a short, lower-case name.
3. Add a row to the table above describing what the bundle exercises.
4. Reference it via ``tests.fixtures.bundles.path("name.zip")`` so
   every consumer goes through the same loader and the path stays
   correct under different test-runner working directories.

## Why these are committed, not symlinked or downloaded

* Symlinks would break the moment the source dataset is regenerated.
* Downloading at test time adds network flake + a hidden dependency.
* Each bundle is a self-contained zip on the order of 1 MB; total
  ~3 MB is fine for the repository and survives `git clone`.
