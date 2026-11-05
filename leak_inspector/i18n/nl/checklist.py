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

"""Dutch translations: manual-review checklist."""

MESSAGES: dict[str, str] = {
    "Manual-review checklist": (
        "Checklist voor handmatige controle"
    ),
    "WCAG 2.2 AA manual-review checklist": (
        "Checklist voor handmatige controle van WCAG 2.2 AA"
    ),
    "These success criteria cannot be decided automatically. Confirm each one by hand on every page below. 'manual' criteria need human judgement outright. Many criteria (both 'manual' and 'partial') also have candidate findings or review pointers in the automated report — cross-check those, they point at the specific elements to verify. Completing this checklist is necessary, but on its own still not a conformance claim.": (
        "Over deze succescriteria kan niet automatisch worden beslist. Bevestig elk ervan handmatig op elke pagina hieronder. 'Handmatige' succescriteria vragen volledig een menselijk oordeel. Voor veel succescriteria ('handmatig' en 'gedeeltelijk') staan er ook kandidaat-bevindingen of controlewijzers in het geautomatiseerde rapport — vergelijk daarmee, ze wijzen de precieze elementen aan om te controleren. Deze checklist afwerken is noodzakelijk, maar op zich nog geen conformiteitsclaim."
    ),
    "{count} criteria to review ({manual} manual, {partial} partial) across {pages} page(s). Work through the questions under each criterion for every page.": (
        "{count} succescriteria te controleren ({manual} handmatig, {partial} gedeeltelijk) op {pages} pagina('s). Werk voor elke pagina de vragen onder elk succescriterium af."
    ),
    "{count} criteria still need a human ({manual} manual, {partial} partial) across {pages} page(s).": (
        "{count} succescriteria vragen nog een menselijke controle ({manual} handmatig, {partial} gedeeltelijk) op {pages} pagina('s)."
    ),
    "{count} criteria": (
        "{count} succescriteria"
    ),
    "No pages were recorded to review.": (
        "Er zijn geen pagina's vastgelegd om te controleren."
    ),
    # -- review questions, per success criterion --------------------------
    # 1.2.1
    "Does the page contain prerecorded audio-only or video-only media? (If not, mark N/A.)": (
        "Bevat de pagina vooraf opgenomen louter-geluid of louter-videobeeld? (Zo niet, markeer als n.v.t.)"
    ),
    "For audio-only, is an equivalent text transcript provided?": (
        "Is er bij louter-geluid een gelijkwaardig transcript in tekst?"
    ),
    "For video-only, is a text or audio description of the visual content provided?": (
        "Is er bij louter-videobeeld een beschrijving in tekst of audio van de visuele content?"
    ),
    # 1.2.2
    "Does the page contain prerecorded video with audio? (If not, mark N/A.)": (
        "Bevat de pagina vooraf opgenomen video met geluid? (Zo niet, markeer als n.v.t.)"
    ),
    "Are synchronized captions provided for all dialogue and important sounds?": (
        "Zijn er gesynchroniseerde ondertitels voor doven en slechthorenden voor alle dialogen en belangrijke geluiden?"
    ),
    # 1.2.3
    "Does the page contain prerecorded video with audio? (If not, mark N/A.)": (
        "Bevat de pagina vooraf opgenomen video met geluid? (Zo niet, markeer als n.v.t.)"
    ),
    "Is an audio description of the important visual detail, or a full text alternative, provided?": (
        "Is er een audiodescriptie van de belangrijke visuele details, of een volledig tekstalternatief?"
    ),
    # 1.2.4
    "Does the page stream live audio content? (If not, mark N/A.)": (
        "Zendt de pagina live audio-content uit? (Zo niet, markeer als n.v.t.)"
    ),
    "Are real-time captions provided for that live audio?": (
        "Zijn er realtime ondertitels voor doven en slechthorenden voor die live audio?"
    ),
    # 1.2.5
    "Does the page contain prerecorded video with audio? (If not, mark N/A.)": (
        "Bevat de pagina vooraf opgenomen video met geluid? (Zo niet, markeer als n.v.t.)"
    ),
    "Is a synchronized audio description track provided for visual information the soundtrack does not convey?": (
        "Is er een gesynchroniseerd audiodescriptiespoor voor visuele informatie die de geluidsband niet overbrengt?"
    ),
    # 1.3.2
    "Read the report's Reading view section (the page linearized in DOM/source order): does the content still read in a meaningful order there?": (
        "Lees de sectie Leesweergave van het rapport (de pagina gelineariseerd in DOM-/bronvolgorde): leest de content daar nog in een betekenisvolle volgorde?"
    ),
    "Does that source order match the intended reading order assistive tech would follow, or does CSS visually reorder content away from it?": (
        "Komt die bronvolgorde overeen met de bedoelde leesvolgorde die hulptechnologieën volgen, of herschikt CSS de content visueel anders?"
    ),
    # 1.3.3
    "Do any instructions rely only on shape, size, or position (e.g. 'the round button', 'the box on the right')?": (
        "Steunen instructies alleen op vorm, grootte of positie (bv. 'de ronde knop', 'het vak rechts')?"
    ),
    "Do any instructions rely only on colour or sound? (cross-check 1.4.1)": (
        "Steunen instructies alleen op kleur of geluid? (vergelijk met 1.4.1)"
    ),
    "Is every such instruction also given in a form that does not require seeing the layout?": (
        "Wordt elke zulke instructie ook gegeven in een vorm waarvoor de opmaak niet gezien hoeft te worden?"
    ),
    # 1.4.1
    "Is colour ever the only means of conveying information (required fields, links, error/success states)?": (
        "Is kleur ooit het enige middel om informatie over te brengen (verplichte velden, links, fout-/successtatus)?"
    ),
    "Are in-text links distinguishable from surrounding text without relying on colour alone?": (
        "Zijn links in lopende tekst te onderscheiden van de omringende tekst zonder alleen op kleur te steunen?"
    ),
    "Is each colour-coded state also signalled by text, icon, or shape?": (
        "Wordt elke status met een kleurcode ook aangegeven met tekst, een pictogram of een vorm?"
    ),
    # 1.4.2
    "Does any audio play automatically for more than 3 seconds? (If none, mark N/A.)": (
        "Speelt er automatisch audio af die langer dan 3 seconden duurt? (Zo niet, markeer als n.v.t.)"
    ),
    "Is there a control to pause, stop, or mute it independently of the system volume?": (
        "Is er een bedieningselement om die audio te pauzeren, te stoppen of het volume te regelen, los van het systeemvolume?"
    ),
    # 1.4.4
    "Zoom text to 200% (browser zoom): is all text still fully readable?": (
        "Zoom de tekst naar 200% (browserzoom): is alle tekst nog volledig leesbaar?"
    ),
    "Is any content or functionality clipped, overlapped, or lost at 200%?": (
        "Wordt bij 200% content of functionaliteit afgesneden, overlapt of verloren?"
    ),
    # 1.4.5
    "Are there images that render text, other than logos/wordmarks? (If none, mark N/A.)": (
        "Zijn er afbeeldingen die tekst weergeven, buiten logo's/woordmerken? (Zo niet, markeer als n.v.t.)"
    ),
    "Could that text be presented as real, styleable text instead? If so, it should be.": (
        "Kan die tekst als echte, opmaakbare tekst worden weergegeven? Zo ja, dan hoort dat zo."
    ),
    # 1.4.10
    "At 320 CSS px width (or 400% zoom), does content reflow to one column with no horizontal scrolling?": (
        "Herschikt de content zich bij 320 CSS-px breedte (of 400% zoom) tot één kolom zonder horizontaal scrollen?"
    ),
    "Is any information or functionality lost when reflowed? (Data tables and maps are exempt.)": (
        "Gaat er bij het herschikken informatie of functionaliteit verloren? (Datatabellen en kaarten zijn uitgezonderd.)"
    ),
    # 1.4.11
    "Do UI component boundaries (button edges, field borders, focus indicators) meet 3:1 contrast against their surroundings?": (
        "Halen de grenzen van componenten van de gebruikersinterface (knopranden, veldranden, focusindicatoren) een contrast van 3:1 met hun omgeving?"
    ),
    "Do meaningful graphical objects (icons, chart segments) meet 3:1 contrast?": (
        "Halen betekenisvolle grafische objecten (pictogrammen, segmenten van grafieken) een contrast van 3:1?"
    ),
    # 1.4.12
    "Apply the WCAG text-spacing overrides (line 1.5×, paragraph 2×, letter 0.12em, word 0.16em): does any text clip or overlap?": (
        "Pas de WCAG-instellingen voor tekstafstand toe (regelhoogte 1,5×, alinea 2×, letter 0,12em, woord 0,16em): wordt er tekst afgesneden of overlapt er tekst?"
    ),
    "Is all content and functionality still available after the spacing change?": (
        "Is alle content en functionaliteit nog beschikbaar na de aangepaste tekstafstand?"
    ),
    # 1.4.13
    "Does hovering or focusing reveal extra content (tooltips, popovers, menus)? (If none, mark N/A.)": (
        "Verschijnt er extra content bij hover of focus (tooltips, popovers, menu's)? (Zo niet, markeer als n.v.t.)"
    ),
    "Can it be dismissed without moving the pointer or focus (e.g. pressing Esc)?": (
        "Kan die content worden weggehaald zonder de aanwijzer of de focus te verplaatsen (bv. met Esc)?"
    ),
    "Does it stay visible while hovered/focused and remain until dismissed?": (
        "Blijft ze zichtbaar zolang er hover of focus is, en blijft ze staan tot ze wordt weggehaald?"
    ),
    # 2.1.1
    "Can you operate every interactive control using the keyboard alone?": (
        "Is elk interactief bedieningselement met alleen het toetsenbord te bedienen?"
    ),
    "Is any action available only by mouse/pointer (hover-only, drag-only)?": (
        "Is er een actie die alleen met muis/aanwijzer beschikbaar is (alleen hover, alleen slepen)?"
    ),
    # 2.1.2
    "Tab through the whole page: can focus always move away from every component with the keyboard alone?": (
        "Tab door de hele pagina: kan de focus altijd met alleen het toetsenbord van elk component weg?"
    ),
    "Do modals and embedded widgets let you leave via keyboard (Esc or Tab)? (cross-check the automated finding)": (
        "Kun je modale vensters en ingesloten widgets met het toetsenbord verlaten (Esc of Tab)? (vergelijk met de geautomatiseerde bevinding)"
    ),
    # 2.1.4
    "Are there single-character key shortcuts (letter, number, or punctuation)? (If none, mark N/A.)": (
        "Zijn er sneltoetsen van één teken (letter, cijfer of leesteken)? (Zo niet, markeer als n.v.t.)"
    ),
    "Can they be turned off, remapped, or made active only when the relevant control has focus?": (
        "Kunnen ze worden uitgeschakeld, anders worden ingesteld, of alleen actief zijn als het betreffende bedieningselement focus heeft?"
    ),
    # 2.2.1
    "Does the page impose any time limit (session timeout, auto-advance, countdown)? (If none, mark N/A.)": (
        "Legt de pagina een tijdslimiet op (sessie-time-out, automatisch doorgaan, aftelling)? (Zo niet, markeer als n.v.t.)"
    ),
    "Can the user turn off, adjust, or extend the limit before it expires?": (
        "Kan de gebruiker de limiet uitschakelen, aanpassen of verlengen voordat ze verstrijkt?"
    ),
    # 2.2.2
    "Is there moving, blinking, scrolling, or auto-updating content lasting more than 5 seconds? (If none, mark N/A.)": (
        "Is er bewegende, knipperende, scrollende of automatisch bijwerkende content die langer dan 5 seconden duurt? (Zo niet, markeer als n.v.t.)"
    ),
    "Can the user pause, stop, or hide it?": (
        "Kan de gebruiker die pauzeren, stoppen of verbergen?"
    ),
    # 2.3.1
    "Does any content flash more than three times in one second? (If none, mark N/A.)": (
        "Flitst er content meer dan drie keer per seconde? (Zo niet, markeer als n.v.t.)"
    ),
    "If it flashes, is the flashing area small and below the general and red-flash thresholds?": (
        "Als er iets flitst: is het flitsende gebied klein en blijft het onder de algemene drempelwaarde en de drempelwaarde voor rode flitsen?"
    ),
    # 2.4.3
    "Tab through the page: does focus move in an order that preserves meaning and operability?": (
        "Tab door de pagina: verplaatst de focus zich in een volgorde die betekenis en bedienbaarheid behoudt?"
    ),
    "After opening a menu or modal, does focus move into it and return sensibly? (cross-check the automated finding)": (
        "Gaat de focus na het openen van een menu of modaal venster daarin, en keert ze daarna logisch terug? (vergelijk met de geautomatiseerde bevinding)"
    ),
    # 2.4.4
    "For each link, is its purpose clear from the link text alone or with its surrounding context?": (
        "Is bij elke link het doel duidelijk uit de linktekst alleen, of samen met de omringende context?"
    ),
    "Are there ambiguous links ('click here', 'read more') whose destination is unclear in context?": (
        "Zijn er dubbelzinnige links ('klik hier', 'lees meer') waarvan de bestemming in de context onduidelijk is?"
    ),
    # 2.4.5
    "Is there more than one way to locate this page in the site (search, sitemap, nav menu, A–Z index)? (Exempt if it is a step in a process.)": (
        "Is er meer dan één manier om deze pagina binnen de site te vinden (zoekfunctie, sitemap, navigatiemenu, A-Z-index)? (Uitgezonderd als het een stap in een proces is.)"
    ),
    "Do those ways actually lead to this page?": (
        "Leiden die manieren echt naar deze pagina?"
    ),
    # 2.4.6
    "Does each heading describe the topic or purpose of the section it introduces?": (
        "Beschrijft elke kop het onderwerp of doel van het onderdeel dat hij inleidt?"
    ),
    "Does each form label describe the purpose of its control? (cross-check the automated finding)": (
        "Beschrijft elk formulierlabel het doel van zijn bedieningselement? (vergelijk met de geautomatiseerde bevinding)"
    ),
    # 2.4.7
    "Tab through the page: is the keyboard focus indicator visible on every focused element?": (
        "Tab door de pagina: is de focusindicator van het toetsenbord zichtbaar op elk element dat focus krijgt?"
    ),
    "Is there any control where the focus indicator disappears? (cross-check the automated finding)": (
        "Is er een bedieningselement waarbij de focusindicator verdwijnt? (vergelijk met de geautomatiseerde bevinding)"
    ),
    # 2.4.11
    "When an element receives focus, is it at least partially visible (not fully hidden behind sticky headers, footers, or overlays)?": (
        "Is een element dat focus krijgt minstens gedeeltelijk zichtbaar (niet volledig verborgen achter vaste kop- of voetbalken of overlays)?"
    ),
    "Check components near the viewport edges especially. (cross-check the automated finding)": (
        "Controleer vooral componenten dicht bij de randen van de viewport. (vergelijk met de geautomatiseerde bevinding)"
    ),
    # 2.5.1
    "Does any function require a multipoint or path-based gesture (pinch, two-finger, swipe along a path)? (If none, mark N/A.)": (
        "Vereist een functie een gebaar met meerdere aanwijspunten of een pad (knijpen, twee vingers, vegen langs een pad)? (Zo niet, markeer als n.v.t.)"
    ),
    "Is there a single-pointer alternative (e.g. a button) for that function?": (
        "Is er voor die functie een alternatief met één aanwijspunt (bv. een knop)?"
    ),
    # 2.5.2
    "For single-pointer actions, does activation happen on the up-event rather than the down-event?": (
        "Gebeurt de activering bij acties met één aanwijspunt bij het loslaten (up-event) in plaats van bij het indrukken (down-event)?"
    ),
    "Can the user abort by moving away before releasing, or undo the action afterwards?": (
        "Kan de gebruiker afbreken door weg te bewegen vóór het loslaten, of de actie achteraf ongedaan maken?"
    ),
    # 2.5.3
    "For controls with a visible text label, does the accessible name contain that visible text?": (
        "Bevat bij bedieningselementen met een zichtbaar tekstlabel de toegankelijke naam die zichtbare tekst?"
    ),
    "Could a speech-input user activate the control by speaking its visible label? (cross-check the automated finding)": (
        "Kan iemand die spraakbesturing gebruikt het bedieningselement activeren door het zichtbare label uit te spreken? (vergelijk met de geautomatiseerde bevinding)"
    ),
    # 2.5.4
    "Is any function triggered by device or user motion (shake, tilt)? (If none, mark N/A.)": (
        "Wordt een functie geactiveerd door beweging van het apparaat of de gebruiker (schudden, kantelen)? (Zo niet, markeer als n.v.t.)"
    ),
    "Is there a conventional control alternative, and can the motion actuation be disabled?": (
        "Is er een alternatief via een gewoon bedieningselement, en kan de bewegingsactivering worden uitgeschakeld?"
    ),
    # 2.5.7
    "Does any function require a dragging movement (sliders, drag-and-drop, reordering)? (If none, mark N/A.)": (
        "Vereist een functie een sleepbeweging (schuifregelaars, slepen en neerzetten, herschikken)? (Zo niet, markeer als n.v.t.)"
    ),
    "Is there a single-tap or click alternative that does not require dragging?": (
        "Is er een alternatief met één tik of klik waarvoor niet gesleept hoeft te worden?"
    ),
    # 2.5.8
    "Are pointer targets at least 24×24 CSS px, or spaced so a 24px circle over one does not overlap a neighbour? (cross-check the automated finding)": (
        "Zijn aanwijsgebieden minstens 24×24 CSS-px, of zo ver uit elkaar dat een cirkel van 24px over het ene gebied geen buur overlapt? (vergelijk met de geautomatiseerde bevinding)"
    ),
    "For any under-size target, does an exception apply (inline in a sentence, essential, or browser-default styling)?": (
        "Geldt er voor elk te klein aanwijsgebied een uitzondering (inline in een zin, essentieel, of standaardopmaak van de browser)?"
    ),
    # 3.1.2
    "Are there passages or phrases in a language different from the page's main language? (If none, mark N/A.)": (
        "Zijn er passages of zinsdelen in een andere taal dan de hoofdtaal van de pagina? (Zo niet, markeer als n.v.t.)"
    ),
    "Does each such passage carry a correct lang attribute?": (
        "Heeft elke zulke passage een correct lang-attribuut?"
    ),
    # 3.2.1
    "Tab onto each control: does merely focusing it change context (open a window, move focus, submit a form)?": (
        "Tab naar elk bedieningselement: verandert de context al door het element alleen focus te geven (een venster openen, de focus verplaatsen, een formulier verzenden)?"
    ),
    "Focusing a control should not, on its own, cause such a change.": (
        "Focus geven aan een bedieningselement mag op zich geen zulke verandering veroorzaken."
    ),
    # 3.2.2
    "Change each form control's value (type, select, toggle): does that alone change context (auto-submit, navigate)?": (
        "Wijzig de waarde van elk formulierelement (typen, selecteren, aan-/uitzetten): verandert de context alleen daardoor (automatisch verzenden, navigeren)?"
    ),
    "If a change of context does occur on input, were users warned beforehand?": (
        "Als er bij invoer een contextverandering optreedt, werden gebruikers daar vooraf voor gewaarschuwd?"
    ),
    # 3.2.3
    "Do navigation components that repeat across pages appear in the same relative order each time?": (
        "Verschijnen navigatiecomponenten die op meerdere pagina's terugkomen telkens in dezelfde relatieve volgorde?"
    ),
    "Compare this page against the other audited pages.": (
        "Vergelijk deze pagina met de andere geauditeerde pagina's."
    ),
    # 3.2.4
    "Are components with the same function identified consistently (same name, icon, and label) across pages?": (
        "Worden componenten met dezelfde functie op alle pagina's consistent geïdentificeerd (zelfde naam, pictogram en label)?"
    ),
    "Compare this page against the other audited pages.": (
        "Vergelijk deze pagina met de andere geauditeerde pagina's."
    ),
    # 3.2.6
    "If a help mechanism exists (contact details, help link, chat), does it appear in the same relative order on every page that offers it?": (
        "Als er een hulpmechanisme is (contactgegevens, hulplink, chat), staat het dan in dezelfde relatieve volgorde op elke pagina die het aanbiedt?"
    ),
    # 3.3.1
    "Trigger a form validation error: is the field in error identified and the problem described in text?": (
        "Veroorzaak een validatiefout in een formulier: wordt het foute veld aangeduid en het probleem in tekst beschreven?"
    ),
    "Is the error conveyed by more than colour alone?": (
        "Wordt de fout op meer dan alleen kleur overgebracht?"
    ),
    # 3.3.2
    "Does every form field have a visible label or instruction explaining what to enter? (cross-check the automated finding)": (
        "Heeft elk formulierveld een zichtbaar label of een instructie die uitlegt wat er ingevuld moet worden? (vergelijk met de geautomatiseerde bevinding)"
    ),
    "Are required fields and any expected format or example indicated?": (
        "Worden verplichte velden en een eventueel verwacht formaat of voorbeeld aangegeven?"
    ),
    # 3.3.3
    "When a validation error is detected and a correction is known, is a suggestion offered to the user?": (
        "Als een validatiefout wordt gedetecteerd en een correctie bekend is, wordt de gebruiker dan een suggestie gegeven?"
    ),
    "(Exempt where suggesting a correction would jeopardise security or purpose.)": (
        "(Uitgezonderd als een correctie voorstellen de beveiliging of het doel in gevaar zou brengen.)"
    ),
    # 3.3.4
    "Does the page create a legal commitment, complete a financial transaction, or modify/delete user data? (If not, mark N/A.)": (
        "Gaat de pagina een juridische verbintenis aan, voltooit ze een financiële transactie, of wijzigt/verwijdert ze gebruikersgegevens? (Zo niet, markeer als n.v.t.)"
    ),
    "Is the submission reversible, checked for errors, or confirmable before it is finalised?": (
        "Is de verzending omkeerbaar, wordt ze op fouten gecontroleerd, of kan ze worden bevestigd voordat ze definitief is?"
    ),
    # 3.3.7
    "In a multi-step process, is information the user already entered auto-populated or selectable rather than re-typed?": (
        "Wordt in een proces met meerdere stappen informatie die de gebruiker al heeft ingevoerd automatisch ingevuld of selecteerbaar gemaakt, in plaats van opnieuw te moeten typen?"
    ),
    "(Exempt when re-entry is essential, e.g. confirming a password.)": (
        "(Uitgezonderd als opnieuw invoeren essentieel is, bv. een wachtwoord bevestigen.)"
    ),
    # 3.3.8
    "Does login require a cognitive function test (recalling a password, solving a puzzle, transcribing a text CAPTCHA)? (If none, mark N/A.)": (
        "Vereist het aanmelden een cognitieve functietest (een wachtwoord onthouden, een puzzel oplossen, een tekst-CAPTCHA overtypen)? (Zo niet, markeer als n.v.t.)"
    ),
    "Is an accessible alternative provided (password-manager paste allowed, email link, biometric, or object-recognition CAPTCHA)?": (
        "Is er een toegankelijk alternatief (plakken vanuit een wachtwoordbeheerder toegestaan, e-maillink, biometrie, of een CAPTCHA met objectherkenning)?"
    ),
    # 4.1.3
    "Do status messages (e.g. 'saved', result counts, form errors) appear without moving keyboard focus?": (
        "Verschijnen statusberichten (bv. 'opgeslagen', aantallen resultaten, formulierfouten) zonder dat de toetsenbordfocus verplaatst?"
    ),
    "Are they exposed via an appropriate role or aria-live region (role=status/alert, aria-live) so assistive tech announces them without a focus change?": (
        "Worden ze beschikbaar gemaakt via een passende rol of aria-live-regio (role=status/alert, aria-live), zodat hulptechnologieën ze voorlezen zonder focuswijziging?"
    ),
}
