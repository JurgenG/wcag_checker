# wcag_checker — record a real human-driven browsing session and audit
# the visited pages for WCAG 2.2 accessibility conformance.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Dutch translations: report text (reporter, reading view, batch summary)."""

MESSAGES: dict[str, str] = {
    # -- reporter: labels shared by every format --------------------------
    "WCAG 2.2 AA audit": "WCAG 2.2 AA-audit",
    "Generated: {when}": "Gegenereerd: {when}",
    "Site: {title}": "Site: {title}",
    "Pages audited ({count}):": "Geauditeerde pagina's ({count}):",
    "Summary": "Samenvatting",
    "Metric": "Kenmerk",
    "Value": "Waarde",
    "A + AA criteria in scope": "Succescriteria A + AA in scope",
    "Automatable (full / partial / manual)": (
        "Automatiseerbaar (volledig / gedeeltelijk / handmatig)"
    ),
    "Criteria with findings": "Succescriteria met bevindingen",
    "Priority": "Prioriteit",
    "Findings": "Bevindingen",
    "Criterion": "Succescriterium",
    "Level": "Niveau",
    "Coverage": "Dekking",
    "This run": "Deze run",
    "Priority overview": "Prioriteitenoverzicht",
    "Occurrences": "Voorkomens",
    "Worst": "Ergste",
    "Severity": "Ernst",
    "Impact": "Impact",
    "Element": "Element",
    "Message": "Melding",
    "URL": "URL",
    "Evidence": "Bewijs",
    "No automated findings.": "Geen geautomatiseerde bevindingen.",
    "(page)": "(pagina)",
    "evidence": "bewijs",
    "evidence: {path}": "bewijs: {path}",
    "element screenshot": "schermafbeelding van het element",
    "impact: {impact}": "impact: {impact}",
    "{label} priority": "Prioriteit {label}",
    # -- reporter: values ---------------------------------------------------
    "error": "fout",
    "warning": "waarschuwing",
    "needs-review": "te controleren",
    "full": "volledig",
    "partial": "gedeeltelijk",
    "manual": "handmatig",
    "FAIL": "NIET VOLDAAN",
    "NEEDS REVIEW": "TE CONTROLEREN",
    "critical": "kritiek",
    "serious": "ernstig",
    "moderate": "matig",
    "minor": "gering",
    "Critical": "Kritiek",
    "High": "Hoog",
    "Medium": "Middel",
    "Review": "Controle",
    "no automated finding": "geen geautomatiseerde bevinding",
    "needs manual review": "handmatige controle nodig",
    "{count} finding(s)": "{count} bevinding(en)",
    "{count} critical": "{count} kritiek",
    "{count} high": "{count} hoog",
    "{count} medium": "{count} middel",
    "{count} needs-review": "{count} te controleren",
    "{count} error": "{count} fout(en)",
    "{count} warning": "{count} waarschuwing(en)",
    # -- reporter: text report ----------------------------------------------
    "Coverage summary": "Samenvatting van de dekking",
    "WCAG 2.2 A + AA criteria in scope: {count}": (
        "Succescriteria WCAG 2.2 A + AA in scope: {count}"
    ),
    "  automatable (full):    {count}": "  automatiseerbaar (volledig):      {count}",
    "  automatable (partial): {count}": "  automatiseerbaar (gedeeltelijk):  {count}",
    "  manual only:           {count}": "  alleen handmatig:                 {count}",
    "Criteria with findings: {count}": "Succescriteria met bevindingen: {count}",
    "By priority: {counts}": "Per prioriteit: {counts}",
    "Findings: {counts}": "Bevindingen: {counts}",
    "Coverage — all WCAG 2.2 A + AA criteria": (
        "Dekking — alle succescriteria van WCAG 2.2 A + AA"
    ),
    "Findings by priority": "Bevindingen per prioriteit",
    # -- reporter: disclaimer and legend --------------------------------------
    (
        "A clean automated run does not imply WCAG 2.2 AA conformance. "
        "Automated tooling decides only part of a subset of the success "
        "criteria; a criterion with no automated finding is not a pass, and "
        "every criterion requires manual review before a conformance claim "
        "can be made."
    ): (
        "Een geautomatiseerde run zonder bevindingen betekent geen conformiteit "
        "met WCAG 2.2 AA. Geautomatiseerde tools beslissen slechts over een "
        "deel van een deel van de succescriteria; een succescriterium zonder "
        "geautomatiseerde bevinding is niet voldaan verklaard, en elk "
        "succescriterium vereist een handmatige controle voordat een "
        "conformiteitsclaim gemaakt kan worden."
    ),
    (
        "Coverage is how much of a criterion automated tooling can decide: "
        "'full' (a clean automated check is meaningful evidence), 'partial' "
        "(tooling flags candidates, a human confirms), 'manual' (no automated "
        "check — human judgement only). This run: 'N finding(s)' are automated "
        "issues to fix or triage; 'no automated finding' means the automatable "
        "part was checked and nothing was flagged — not a pass; 'needs manual "
        "review' means it was not decided automatically. Work the manual-review "
        "checklist below for every 'partial'/'manual' criterion regardless."
    ): (
        "Dekking is hoeveel van een succescriterium geautomatiseerde tools "
        "kunnen beslissen: 'volledig' (een geautomatiseerde controle zonder "
        "bevindingen is betekenisvol bewijs), 'gedeeltelijk' (tools signaleren "
        "kandidaten, een mens bevestigt), 'handmatig' (geen geautomatiseerde "
        "controle — alleen menselijk oordeel). Deze run: 'N bevinding(en)' zijn "
        "geautomatiseerde problemen om op te lossen of te beoordelen; 'geen "
        "geautomatiseerde bevinding' betekent dat het automatiseerbare deel is "
        "gecontroleerd en niets is gesignaleerd — dat is geen 'voldaan'; "
        "'handmatige controle nodig' betekent dat het niet automatisch is "
        "beslist. Werk de checklist voor handmatige controle hieronder in elk "
        "geval af voor elk 'gedeeltelijk'/'handmatig' succescriterium."
    ),
    # -- reporter: JIRA tickets -----------------------------------------------
    "{count} occurrence(s)": "{count} voorkomen(s)",
    "Field": "Veld",
    "Type": "Type",
    "Accessibility review (candidate)": "Toegankelijkheidscontrole (kandidaat)",
    "Accessibility bug": "Toegankelijkheidsfout",
    "WCAG 2.2 criterion": "Succescriterium WCAG 2.2",
    "{id} {name} (level {level})": "{id} {name} (niveau {level})",
    "Automatability": "Automatiseerbaarheid",
    "{count} on {pages} page(s)": "{count} op {pages} pagina('s)",
    "Labels": "Labels",
    "Description": "Beschrijving",
    (
        "WCAG 2.2 **{id} {name}** (level {level}) needs a human decision: the "
        "automated audit flagged {count} candidate(s) across {pages} page(s) "
        "but cannot confirm this criterion on its own. Triage each, then fix "
        "or dismiss."
    ): (
        "WCAG 2.2 **{id} {name}** (niveau {level}) vraagt een menselijke "
        "beslissing: de geautomatiseerde audit signaleerde {count} "
        "kandida(a)t(en) op {pages} pagina('s), maar kan dit succescriterium "
        "niet zelf bevestigen. Beoordeel elke kandidaat en los hem op of wijs "
        "hem af."
    ),
    (
        "WCAG 2.2 success criterion **{id} {name}** (level {level}) is not "
        "satisfied. The automated audit flagged {count} occurrence(s) across "
        "{pages} page(s)."
    ): (
        "Aan WCAG 2.2-succescriterium **{id} {name}** (niveau {level}) wordt "
        "niet voldaan. De geautomatiseerde audit signaleerde {count} "
        "voorkomen(s) op {pages} pagina('s)."
    ),
    "Affected elements": "Betrokken elementen",
    "Acceptance criteria": "Acceptatiecriteria",
    "Every element above satisfies WCAG 2.2 {id} {name}.": (
        "Elk element hierboven voldoet aan WCAG 2.2 {id} {name}."
    ),
    "A re-run of the audit reports no findings for this criterion.": (
        "Een nieuwe audit meldt geen bevindingen meer voor dit succescriterium."
    ),
    (
        "A person has confirmed this criterion — the tool flags candidates "
        "here but cannot decide it on its own."
    ): (
        "Een persoon heeft dit succescriterium bevestigd — de tool signaleert "
        "hier kandidaten, maar kan er niet zelf over beslissen."
    ),
    "Generated by wcag-checker at {when}.": "Gegenereerd door wcag-checker op {when}.",
    "Generated by wcag-checker.": "Gegenereerd door wcag-checker.",
    # -- axe_runner: framing around axe-core's own messages -------------------
    "violation": "overtreding",
    "needs review": "te controleren",
    "See {url}": "Zie {url}",
    # -- text_view: reading view ----------------------------------------------
    "Reading view (manual-review aid)": "Leesweergave (hulpmiddel voor handmatige controle)",
    (
        "This is an approximate *linearized reading view*: the page walked in "
        "DOM source order with a simplified accessible name for each heading, "
        "link, button, image, form field and landmark — broadly what a screen "
        "reader or text-only browser encounters reading top to bottom. It is a "
        "manual-review aid, NOT a screen-reader test and NOT a conformance "
        "check. It cannot tell you whether a name is *meaningful*, whether this "
        "order matches the *visual* layout (CSS can reorder content), or how any "
        "assistive technology actually announces the page. ⚠ marks an "
        "element that has no accessible name for you to check by hand."
    ): (
        "Dit is een benaderende *gelineariseerde leesweergave*: de pagina "
        "doorlopen in de volgorde van de DOM-broncode, met een vereenvoudigde "
        "toegankelijke naam voor elke kop, link, knop, afbeelding, "
        "formulierveld en landmark — ruwweg wat een schermlezer of tekstbrowser "
        "van boven naar beneden tegenkomt. Het is een hulpmiddel voor "
        "handmatige controle, GEEN schermlezertest en GEEN "
        "conformiteitscontrole. Het kan niet zeggen of een naam *betekenisvol* "
        "is, of deze volgorde overeenkomt met de *visuele* opmaak (CSS kan "
        "content herschikken), of hoe hulptechnologieën de pagina werkelijk "
        "voorlezen. ⚠ markeert een element zonder toegankelijke naam, om "
        "handmatig te controleren."
    ),
    "no alt attribute": "geen alt-attribuut",
    "decorative (empty alt)": "decoratief (lege alt)",
    "iframe has no title": "iframe heeft geen title",
    "name from placeholder only": "naam alleen uit placeholder",
    "name from title attribute": "naam uit title-attribuut",
    "no label": "geen label",
    "no accessible name": "geen toegankelijke naam",
    "unnamed": "naamloos",
    "empty heading": "lege kop",
    "No visible content was extracted from this page.": (
        "Van deze pagina werd geen zichtbare content opgehaald."
    ),
    "Reading view truncated at {count} elements; the page has more.": (
        "Leesweergave afgekapt na {count} elementen; de pagina bevat er meer."
    ),
    (
        "{headings} heading(s), {landmarks} landmark(s), {links} link(s), "
        "{buttons} button(s), {images} image(s) ({unnamed_images} without a "
        "name), {fields} form field(s) ({unlabelled_fields} without a label)."
    ): (
        "{headings} kop(pen), {landmarks} landmark(s), {links} link(s), "
        "{buttons} knop(pen), {images} afbeelding(en) ({unnamed_images} "
        "zonder naam), {fields} formulierveld(en) ({unlabelled_fields} zonder "
        "label)."
    ),
    # -- batch: summary across sites ----------------------------------------
    "WCAG 2.2 AA batch audit": "WCAG 2.2 AA-batchaudit",
    "Source: {source}": "Bron: {source}",
    "{total} site(s): {audited} audited, {failed} failed.": (
        "{total} site(s): {audited} geauditeerd, {failed} mislukt."
    ),
    "audited": "geauditeerd",
    "failed": "mislukt",
    "Site": "Site",
    "Status": "Status",
    "Criteria": "Succescriteria",
    "Error": "Fout",
    "Warning": "Waarschuwing",
    "Needs-review": "Te controleren",
    (
        "A clean automated run does not imply WCAG 2.2 AA conformance. These "
        "per-site totals count only automated findings; every site still needs "
        "the manual-review checklist worked through before any conformance "
        "claim."
    ): (
        "Een geautomatiseerde run zonder bevindingen betekent geen conformiteit "
        "met WCAG 2.2 AA. Deze totalen per site tellen alleen geautomatiseerde "
        "bevindingen; voor elke site moet de checklist voor handmatige "
        "controle nog worden afgewerkt voordat een conformiteitsclaim mogelijk "
        "is."
    ),
}
