# Scoring rubric

`leak_inspector` attaches a small composite score to every analyzed site so non-technical readers can answer *"how is this site doing?"* in one glance:

```
Total: 66 / 100  ·  🛡️ 81  🔐 64  🕶️ 54
resilience · security · privacy
```

This document is the single reference for the scoring model: the operational model (how the number is computed), the full 33-criteria impact rubric (the 0–5 scale, per domain, with worked examples), and the deliberate trade-offs. The engine is `leak_inspector/report/score_v2.py`; per-module ratings live next to each module's class; non-module signal ratings live in the signal assembler.

## The model in one paragraph

Every third party the page contacts is a **module** (GA4, Facebook Pixel, Matomo, …) and every adverse posture fact is a **signal** (missing CSP, extra-EU hosting, tracking after a consent reject, …). Each carries a curated **impact rating** — a triple `(privacy, security, resilience)`, each `0.0`–`5.0` in half-point steps — saying how much harm it does on each domain. For one capture, every fired module and signal **deducts** its impact; the per-domain penalties **cumulate** (many small bad things add up to a bad site); each dimension's summed penalty is mapped through a **logistic curve** to a 0–100 score; and the three dimensions combine by **cube root** into the total.

## Two ground rules

These carry over from the rest of the project and govern every rating:

1. **Certainty rule.** A rating reflects what the module *does as embedded* — documented behavior and what our captures show on the wire — never reputation or speculation. A setting we cannot observe on the wire does not exist for scoring; the base triple is the documented default. When two ratings are defensible, take the lower and note why in the module docstring. (The same rule gates signals: an un-enriched bundle is never penalised for posture we never measured.)
2. **Capability, not context.** A module's rating is a property of the module — what this vendor/technique can do with what it receives — independent of the visited site. Site context (a sensitive site, pre-consent firing) belongs to the *aggregation* step, not the per-module number.

## How the total is computed

Three independent dimensions, each 0–100:

- **🛡️ Resilience** — how exposed the operator is to actors outside their own legal control (foreign-jurisdiction vendors, web host / mail / DNS located or registered outside the EU, lock-in).
- **🔐 Security** — how much attack surface the site carries (missing hardening headers, EOL platform, unpinned third-party code, missing SRI).
- **🕶️ Privacy** — how much visitor data leaves to third parties, and whether it does so lawfully (consent).

For each dimension:

```
penalty   = Σ impact of every fired module + signal on that domain
score(P)  = 100 / (1 + e^((P − p50) / s))          # the logistic curve
```

with **`p50 = 11`** (the penalty that scores 50) and **`s = 5`** (the steepness) — `DEFAULT_P50` / `DEFAULT_S` in `score_v2.py`. The total is the geometric mean of the three:

```
total = ³√(resilience × security × privacy)        # all three 0–100
```

Displayed scores are **ceil-rounded**, which makes the curve's asymptotes honest in the printed number: a penalty-free dimension reaches `ceil(90.0) = 91` (100 — true perfection — is never printed), and any site with *any* penalty ceils to ≥ 1 (0 is never printed either). The reachable printed range is **1–91**.

Three properties fall out of this:

1. **Both ends are asymptotic.** The closer a dimension is to 100 or to 0, the less a further penalty moves it; the steepest response is in the middle (around `p50`). Going from excellent to perfect, and from bad to rock-bottom, are both hard — most of the discrimination happens in the middle.
2. **Cumulation, not caps.** A site running twenty small trackers *should* score badly; the penalty just keeps summing. There are no hard caps on the report path — the curve produces the "tracking-after-reject is a 1/100 privacy site" effect organically (a heavy enough penalty maps to ~0).
3. **Imbalance is punished by the cube root.** A site that is sovereign and well-secured but a privacy disaster cannot hide behind its two good dimensions — `³√(81 × 64 × 5) ≈ 26`, far below the arithmetic mean. Uniform competence is rewarded; one rotten dimension drags the whole score down.

> A linear variant (`compute_score_v2`, `dimension = max(0, 10 − Σ impacts)` with per-dimension caps) exists for its own tests only. The report path is the logistic model above.

## The 33-criteria impact rubric

The rating scale is **0.0 (no impact) to 5.0 (disastrous impact)** in half-point steps → 11 values, across the three domains → 33 evaluation criteria. Integer steps are qualitative classes ("what *kind* of harm is possible?"); the half-points between them are real criteria of their own, so any module lands on exactly one line.

### 🕶️ Privacy — what does this module learn about the visitor, and how far does it travel?

Grows along **data categories** (connection metadata → telemetry → behavioral → PII), **persistence** (nothing → session → durable ID), **reach** (one site → vendor network → the open ad ecosystem), and **honesty** (transparent → evasive).

| Score | Criterion |
|---:|---|
| **0.0** | **Nothing leaves the operator.** First-party, self-hosted resource; no visitor data reaches any other organisation. *(self-hosted assets, a cookieless self-hosted banner)* |
| **0.5** | **Connection metadata to the operator's own processor.** IP / UA / Referer reach an external party that is contractually the operator's EU-bound supplier. An extra log file, not an extra interest. *(Icordis asset hosts)* |
| **1.0** | **Connection metadata to an unrelated third party.** The fetch discloses *this visitor saw this page* to a party with its own interests, but no identifier is set and nothing is stored. *(Google Fonts, gstatic, jsDelivr, OSM tiles)* |
| **1.5** | **Anonymous technical telemetry.** Purposeful collection beyond the bare fetch — error reports, timings, aggregate counts — tied to the session at most; no durable ID. *(Sentry, cookieless counters, CMP consent beacons)* |
| **2.0** | **Pseudonymous profile under the operator's control.** Durable visitor ID with cross-page history, in infrastructure the operator runs; no other party can read or join it. *(self-hosted Matomo, self-hosted Snowplow)* |
| **2.5** | **Pseudonymous profile at a contained vendor.** Durable ID + history at an analytics vendor, held per-customer, not joined across clients or sold on. *(hosted Matomo Cloud, Piano Analytics)* |
| **3.0** | **Behavioral profile under a self-interested controller.** Durable ID, full visit paths at a vendor that uses the data for its own purposes. *(GA4, Bing UET, Azure App Insights with user IDs)* |
| **3.5** | **Profile joined to a platform identity.** The vendor can connect this visit to a *known account* in its own logged-in cookie pool. *(LinkedIn Insight, Google Ads conversion tags, embedded YouTube)* |
| **4.0** | **Cross-site tracking by design.** The module's purpose is joining this visit to a web-wide profile: third-party cookies, ID syncing, redirect chains to further partners. *(Facebook Pixel, DoubleClick, Adobe AAM/demdex, ID5, LiveRamp, Criteo)* |
| **4.5** | **Indiscriminate capture or deliberate evasion.** Session replay ingesting keystrokes/forms/PII — or any tracker wrapped in a consent-evading technique (CNAME cloak, first-party proxy). Cheating moves a tracker here regardless of payload. *(Hotjar, FullStory, Clarity, Contentsquare; any cloaked vendor)* |
| **5.0** | **Identified-person data ships out.** Actual PII — email, name, account/national identifiers — or fields that trivially deanonymize, sent to a third-party controller. *(form-data harvesting, advanced-matching pixels fed login email)* |

### 🔐 Security — how much attack surface does embedding this module add?

About **what an attacker gains** if the module or its delivery chain is compromised. Integrity controls (SRI, pinning, sandboxing) move a module *down*; unpinned executable reach and form access move it *up*.

| Score | Criterion |
|---:|---|
| **0.0** | **No external code, no external fetch.** Self-hosted, in the operator's own deploy pipeline. Zero marginal surface. |
| **0.5** | **Non-executable static content.** External images/fonts/media. A compromised host can swap pixels, but delivers nothing the browser executes. *(font/CDN image hosts, map tiles)* |
| **1.0** | **Style-capable or integrity-pinned content.** External CSS (selector exfiltration / UI redressing, no execution), or external JS *carrying SRI* (tampered body refused). *(third-party stylesheets; SRI-pinned libraries)* |
| **1.5** | **Sandboxed executable content.** Vendor code inside a cross-origin iframe without first-party DOM access. Compromise hurts the frame, not the page. *(embedded maps/players, hCaptcha/Turnstile frames)* |
| **2.0** | **Unpinned first-party script, narrow and disciplined.** Page-origin code without SRI, but a small/stable single-purpose API from a vendor with a strong patch record. *(reCAPTCHA loader, single-purpose embed snippets)* |
| **2.5** | **Unpinned first-party script, ordinary vendor.** The default analytics snippet: full-origin code the vendor can change anytime, no integrity check, no sandbox — the canonical supply-chain exposure. *(GA4/gtag, vendor-hosted Matomo JS, most marketing tags)* |
| **3.0** | **Code loader / broad-access script.** A module whose *function* is to load further code (tag managers) or that routinely touches DOM/inputs/navigation. *(Google Tag Manager, Cloudflare Zaraz, script-injecting CMPs)* |
| **3.5** | **Input-capturing script by design.** Session replay / form analytics whose feature set *is* keylogging: hooks inputs, serializes forms, screenshots the DOM. *(Hotjar, FullStory, Clarity, Contentsquare)* |
| **4.0** | **Ad-tech long tail / transitive fourth parties.** Executable or redirect-chained content from networks the operator cannot even enumerate. Malvertising's industrialised path. *(AAM sync-chain partners, openx/pubmatic/appnexus-class exchanges)* |
| **4.5** | **Abandoned, ownerless or once-burned infrastructure.** The dependency's *governance* has failed — domain/package changed hands, vendor dissolved, or already shipped malicious code once. *(polyfill.io-class hosts, claimable CNAME targets)* |
| **5.0** | **Actively hostile or attacker-claimable now.** Currently serving malicious payloads, expired and registerable, or pointing at infrastructure anyone can claim. Site compromise as a standing condition. |

### 🛡️ Resilience — how much operator control is lost by depending on this module?

Measures **dependency and jurisdiction**: who can switch this capability off, subpoena what flows through it, or change its terms. Grows along **replaceability** (commodity → lock-in → load-bearing), **jurisdiction** (operator's own → EU → adequacy → high-risk US/CN/RU), and **what is at stake** (cosmetics → measurement → the service itself).

| Score | Criterion |
|---:|---|
| **0.0** | **Self-hosted, operator-owned.** No external party can withdraw, alter or observe it. *(self-hosted Matomo, first-party assets, self-hosted consent banner)* |
| **0.5** | **Commodity EU supplier, operator-substitutable.** An EU-jurisdiction party under contract, doing what any hosting shop could take over next month. *(Icordis asset hosts, an EU CDN for static files)* |
| **1.0** | **Independent EU third party, no lock-in.** A separate EU vendor for a function with drop-in alternatives and no state worth migrating. *(EU-hosted SaaS analytics without kept history, EU widget vendors, paragov shared services)* |
| **1.5** | **Adequacy-country vendor, or EU vendor with real switching costs.** A non-EU adequacy jurisdiction (UK/CH/JP — one review away from not), or EU-based but deeply integrated. |
| **2.0** | **High-risk-jurisdiction vendor for a cosmetic function.** US/CN/RU service doing something trivially self-hostable; the dependency is pure habit. *(Google Fonts, gstatic, jsDelivr, Cloudflare cdnjs)* |
| **2.5** | **High-risk-jurisdiction vendor for a supporting feature.** Bot protection, embedded maps, video — replacements exist but cost real work. *(reCAPTCHA, Google Maps, embedded YouTube)* |
| **3.0** | **Foreign vendor as the measurement layer.** Analytics history, dashboards and KPIs accumulate inside a US/CN/RU platform; lock-in compounds yearly. *(GA4 as the only analytics)* |
| **3.5** | **Operational dependence on a foreign platform's ecosystem.** Marketing/outreach built on one foreign vendor's network, with joint-controllership the operator cannot contract away. *(Facebook Pixel + audience tooling, Google Ads as the outreach channel)* |
| **4.0** | **Site functionality breaks without the foreign vendor.** Login, search, payment, booking or the service chatbot runs on US/CN/RU infrastructure — an outage stops the service. *(third-party SSO as the only login, a US-cloud chatbot fronting citizen services)* |
| **4.5** | **Critical public-service function, foreign-controlled, no exit.** As 4.0, but no tested fallback, no exportable data, and personal data of the served population flowing through as a matter of course. |
| **5.0** | **Single foreign point of failure holding identified citizen data.** The whole service stands or falls with one high-risk-jurisdiction provider *and* identified personal data lives inside it. The precise scenario sovereignty policy exists to prevent. |

## Impact ratings: modules

Each tracker module declares an `impact_rating` triple, rated against the rubric above and justified in a comment beside it. The axes are deliberately independent: a module can be a privacy non-event and a security disaster (polyfill), or invasive yet sovereign (self-hosted Matomo).

| Module | 🕶️ | 🔐 | 🛡️ | Reading |
|---|---:|---:|---:|---|
| self-hosted Matomo | 2.0 | 0.0 | 0.0 | profiles visitors, but everything stays home |
| Google Fonts | 1.0 | 1.0 | 2.0 | presence leak; serves CSS; US habit-dependency |
| GA4 (plain) | 3.0 | 2.5 | 3.0 | self-interested controller; unpinned snippet; measurement lock-in |
| Facebook Pixel | 4.0 | 2.5 | 3.5 | cross-site by design; platform dependence |
| Hotjar | 4.5 | 3.5 | 1.5 | session replay ingests PII; EU vendor |
| Adobe AAM (demdex) | 4.0 | 4.0 | 3.0 | ID-sync hub; unenumerable fourth parties |
| Icordis (LCP) | 0.5 | 0.5 | 0.5 | operator's own EU asset host |
| polyfill-fastly | 1.0 | 4.5 | 2.0 | little data, catastrophic supply-chain governance |

### Per-capture variants

A module may select a **variant** rating from its own hits when the capture shows a configuration that changes the impact — gated on wire-observable evidence only (the certainty rule: a setting we cannot see does not exist; the base triple is the documented default). The load-bearing example is **GA4**, whose `effective_rating(hits)` picks a privacy variant by descending precedence, first match wins (security and resilience stay `2.5 / 3.0` throughout — only privacy moves):

| Variant | Wire evidence | 🕶️ privacy | Reading |
|---|---|---:|---|
| Enhanced Conversions | `em` / `ecid` observed | **5.0** | an identified-person key shipped — the gravest reality; dominates a same-batch `gcs=G100` (if it's on the wire, it went) |
| Evasion | cloak / proxy marker | **4.5** | cheating is rated, not just payload; can only raise |
| User-ID join | `uid` | **3.5** | pseudonym tied to a known account |
| Consent-denied | every `gcs`-reporting beacon is `G100` | **1.5** | no durable client-id persists |
| *(base)* | none of the above | **3.0** | GA4 free-running default |

## Impact ratings: non-module signals

Everything that costs points outside the module registry carries the same kind of triple, declared next to the signal's own emitter. A signal fires only when the underlying data is **present and adverse** (the certainty rule — an un-enriched bundle is never penalised for posture we never measured), and the cookie/consent signals fire **once per offending vendor** so they cumulate.

| Signal | domain | impact | notes |
|---|---|---:|---|
| `https_broken` | security | 3.0 | no transport encryption |
| `tls_cert_invalid` | security | 2.0 | certificate fails validation (expired / self-signed / untrusted CA / hostname mismatch) — TLS present but unauthenticated |
| `csp_missing` / `dmarc_weak` / `tls_legacy_protocol` | security | 1.0 | meaningful hardening gaps (`tls_legacy_protocol`: deprecated TLS 1.0/1.1 accepted) |
| `tls_cert_expiring_soon` | resilience | 0.5 | valid certificate expires within 14 days — imminent-outage risk |
| `hsts_missing`, `xcto_missing`, `xfo_missing`, `permissions_policy_missing`, `security_txt_missing` | security | 0.5 | minor hardening gaps |
| `spf_weak`, `caa_missing`, `mta_sts_missing` | security | 0.5 each | email + DNS hygiene (NIS2 Art. 21(2)(g)/(h), CCB CyberFundamentals): SPF missing or `+all`/`?all`; no CAA issuance restriction; no MTA-STS policy (MX-gated — inbound-only control) |
| `dns_single_nameserver` | resilience | 0.5 | only one authoritative nameserver (RFC 2182 wants ≥2) — resolution single-point-of-failure |
| `referrer_policy_missing` | privacy + security | 0.5 / 0.5 | leaks the URL to third parties *and* weakens framing |
| `dnssec_unsigned` | security + resilience | 0.5 / 0.5 | integrity + hijack exposure |
| `eol_platform` | security | 5.0 | unpatched known-CVE surface |
| `missing_sri_script` / `_stylesheet` | security | 1.0 / 0.5 | supply-chain |
| `{host,mail,dns}_physical_extra_eu` | resilience | 2.0 each | component's server geolocates outside the EU |
| `{host,mail,dns}_jurisdiction_extra_eu` | resilience | 3.0 each | component's ASN is registered outside the EU (CLOUD Act / FISA reach) |
| `no_ipv6` | resilience | 0.5 | primary host is IPv4-only (no AAAA) — minor reachability gap |
| `persistent_xs_cookie` | privacy | 3.0 | per setting vendor |
| `forwarded_tracking_cookie` | privacy | 1.0 | cloaked first-party cookie, per vendor |
| `pre_consent_tracking` | privacy | 4.0 | per vendor, before the decision |
| `post_reject_tracking` | privacy | 5.0 | per vendor, after an explicit reject — the starkest violation |

## How ratings are organised

- **Each module / signal carries its own triplet, beside its definition.** A module's `impact_rating: ImpactRating` sits next to `vendor` / `legal_jurisdiction`, so the rating lives with the docstring that justifies it and every change goes through normal code review. Non-module signals declare their triple where the signal is emitted. A test asserts every module and every signal carries a complete `(privacy, security, resilience)` triple.
- **Deductions count once per product, not per vendor.** GA4 + Google Ads + DoubleClick = three deductions: each embedded product is its own decision and its own surface, regardless of hit count. Unrated modules deduct nothing but are still named.
- **Non-module signals use the same vocabulary** as modules — one 33-criteria rubric for everything that costs points.

## Un-enriched bundles score nothing

A bundle without transport **or** DNS posture (never enriched) scores `None`, not a number: crediting security/resilience we never measured would mislead. The report says "not enough data to score — run `leak-inspector enrich`" instead.

## Worked example — kbc (66 / 100)

```
Total: 66 / 100  ·  🛡️ 81  🔐 64  🕶️ 54
Biggest win: Remove or replace Adobe Experience Cloud (−4 privacy)
  Penalty breakdown:
    🛡️ resilience 81/100   Adobe Experience Cloud −3, AppNexus −2.5, …
    🔐 security   64/100   Adobe Experience Cloud −4, AppNexus −4, …
    🕶️ privacy    54/100   Adobe Experience Cloud −4, AppNexus −4, TrustArc −1.5
```

The detailed report itemises every `(detail, −penalty)` pair behind each dimension score, so the number is always fully explained.

## The "Biggest win" line

`compute_top_action` names the single deduction whose removal helps most — the largest-impact module or signal — phrased by kind ("Remove or replace Microsoft Clarity (−4.5 privacy)"; "Address: …" for a signal). It is the one concrete step an operator can take that moves the score the most.

## What the score is NOT

- **Not a compliance verdict.** A high score is not legal advice; a low one is not proof of an infringement. It is a posture summary.
- **Not a measure of intent.** The model rates what a tracker *can* do with what it receives (capability), not what the operator meant.
- **Not comparable across browsers.** Every rating was calibrated on Firefox captures (ETP on); a Chromium capture would see a different tracker set.