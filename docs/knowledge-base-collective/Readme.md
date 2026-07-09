# Tracker & module knowledge base

One page per `leak_inspector` tracker/module: what the third party is, why an operator deploys it, what it costs across the tool's three scoring domains, and what to do about it (keeping it vs replacing it).

## The three domains

Every third party is rated on three independent 0–5 penalty axes (higher is worse). See `SCORING.md` for the full model.

| Axis | Question it answers |
|---|---|
| 🕶️ **Privacy** | How much visitor data leaves to this third party, and whether it does so lawfully (consent). |
| 🔐 **Security** | How much attack surface it adds (code in your origin, supply-chain governance, missing pinning). |
| 🛡️ **Resilience** | How exposed the operator is to actors outside their own legal control (foreign jurisdiction, lock-in). |

A penalty triple is written `(🕶️ privacy, 🔐 security, 🛡️ resilience)`.

## Sections

- **Web Analytics & RUM** — page-view / behavioural analytics and real-user monitoring (GA4, Matomo, Plausible, Yandex, …).
- **Session Replay** — session-replay / experience-analytics tools (Clarity, FullStory, Contentsquare, Hotjar).
- **Advertising** — social-platform conversion pixels (Meta Pixel).
- **Tag Managers** — control-layer containers that load other tags (GTM, Commanders Act, Cloudflare Zaraz).
- **CDN & Hosted Assets** — third-party hosts for fonts, scripts, libraries and images (self-host / SRI).
- **Website Builders** — "click-together" hosted site platforms whose own CDN serves the whole site (Wix, Squarespace, WordPress.com, Weebly, Webflow, Jimdo).
- **Maps & Embeds** — embedded maps and media (Google/Bing/Apple Maps, OpenStreetMap, YouTube).
- **CRM & Marketing Automation** — CRM/email platforms that capture form data (HubSpot, Mailchimp, Mailjet, Eloqua).
- **Chat & Support Widgets** — embedded help-center / chat widgets (Zendesk, Oswald.ai, Oniroco, ChatHive).
- **Engagement Widgets** — share buttons, surveys, web-push (AddToAny, SurveyMonkey, WonderPush).
- **Accessibility Widgets** — text-to-speech / accessibility-overlay widgets (ReadSpeaker, Browsealoud, UserWay).
- **CAPTCHA & Bot Defense** — bot challenges / device fingerprinting (reCAPTCHA, hCaptcha, Turnstile).
- **Consent Management Platforms** — consent banners; hosted CMPs vs self-hosted first-party banners.
- **Ad-tech** — programmatic advertising, SSPs/DSPs, identity graphs, DMPs, attribution.
- **Public Sector** — government & para-government services (EU, Belgian federal/regional, intercommunal IT) — the low-penalty, sovereign end.
- **Civic & Municipal Platforms** — commercial (often EU/Belgian) platforms public bodies embed to serve citizens (Letsgocity).
- **Other** — a payment SDK and the `google.com` catch-all.
- **Site Posture** — the scoring **signals**: posture facts about the operator's *own* site (headers, DNS/email, SRI, server sovereignty, consent timing). Not third parties — a different template (what / why / how to fix).

> In Nextcloud Collectives the page tree in the sidebar mirrors these folders; each `Readme.md` is the landing page for its section.
