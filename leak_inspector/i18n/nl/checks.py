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

"""Dutch translations: finding messages of the custom checks."""

MESSAGES: dict[str, str] = {
    # --- media ---------------------------------------------------------------
    "yes": "ja",
    "no": "nee",
    "A <video> element is present. Detected text tracks — captions: "
    "{captions}, subtitles: {subtitles}, descriptions: {descriptions}. "
    "WCAG 1.2.3 needs an audio description or a full text alternative for "
    "information conveyed visually — confirm one is provided (it may be a "
    "described version or transcript, not a <track>, so a human must check). "
    "Captions (1.2.2) are evaluated separately.": (
        "Er staat een <video>-element op de pagina. Gevonden tekstsporen — "
        "ondertitels voor doven en slechthorenden: {captions}, ondertitels: "
        "{subtitles}, beschrijvingen: {descriptions}. WCAG 1.2.3 vereist een "
        "audiodescriptie of een volledig tekstalternatief voor informatie die "
        "visueel wordt overgebracht — bevestig dat er een is (dat kan een "
        "versie met audiodescriptie of een transcript zijn in plaats van een "
        "<track>, dus een mens moet dit controleren). Ondertitels (1.2.2) "
        "worden apart beoordeeld."
    ),
    "(It also declares text track(s): {kinds}.)": (
        "(Het declareert ook tekstspoor/-sporen: {kinds}.)"
    ),
    "An <audio> element is present. If it is prerecorded audio-only, WCAG "
    "1.2.1 requires an equivalent text transcript — confirm one is provided "
    "(a transcript elsewhere on the page cannot be detected automatically).": (
        "Er staat een <audio>-element op de pagina. Als het vooraf opgenomen "
        "louter-geluid is, vereist WCAG 1.2.1 een gelijkwaardig transcript — "
        "bevestig dat er een is (een transcript elders op de pagina kan niet "
        "automatisch worden gedetecteerd)."
    ),
    "A {provider} video embed is present, but its contents cannot be "
    "inspected automatically (cross-origin <iframe>). Confirm synchronized "
    "captions are available (WCAG 1.2.2).": (
        "Er staat een ingesloten {provider}-video op de pagina, maar de inhoud "
        "ervan kan niet automatisch worden onderzocht (cross-origin <iframe>). "
        "Bevestig dat gesynchroniseerde ondertitels voor doven en "
        "slechthorenden beschikbaar zijn (WCAG 1.2.2)."
    ),
    "A {provider} video embed is present, but its contents cannot be "
    "inspected automatically (cross-origin <iframe>). Confirm an audio "
    "description or full text alternative is available (WCAG 1.2.3).": (
        "Er staat een ingesloten {provider}-video op de pagina, maar de inhoud "
        "ervan kan niet automatisch worden onderzocht (cross-origin <iframe>). "
        "Bevestig dat een audiodescriptie of een volledig tekstalternatief "
        "beschikbaar is (WCAG 1.2.3)."
    ),
    "An <iframe> embed (from {host}, title “{title}”) could not be audited "
    "automatically.": (
        "Een ingesloten <iframe> (van {host}, titel “{title}”) kon niet "
        "automatisch worden geaudit."
    ),
    "An <iframe> embed (from {host}) could not be audited automatically.": (
        "Een ingesloten <iframe> (van {host}) kon niet automatisch worden "
        "geaudit."
    ),
    "An <iframe> embed (with no external src, title “{title}”) could not be "
    "audited automatically.": (
        "Een ingesloten <iframe> (zonder externe src, titel “{title}”) kon "
        "niet automatisch worden geaudit."
    ),
    "An <iframe> embed (with no external src) could not be audited "
    "automatically.": (
        "Een ingesloten <iframe> (zonder externe src) kon niet automatisch "
        "worden geaudit."
    ),
    "If it presents time-based media (audio or video), WCAG 1.2.1–1.2.5 "
    "apply — review it manually; if it is not media (e.g. a map, form, or "
    "advert), mark N/A.": (
        "Als het op tijd gebaseerde media toont (audio of video), zijn WCAG "
        "1.2.1–1.2.5 van toepassing — controleer het handmatig; als het geen "
        "media is (bv. een kaart, formulier of advertentie), markeer het als "
        "n.v.t."
    ),
    # --- pointers ------------------------------------------------------------
    "No ARIA live region (role=status/alert/log or aria-live) was found. If "
    "the page shows status messages without reloading (form errors, 'saved', "
    "result counts, cart updates), they are probably not announced to screen "
    "readers — check WCAG 4.1.3.": (
        "Er is geen ARIA-live-regio (role=status/alert/log of aria-live) "
        "gevonden. Als de pagina statusberichten toont zonder te herladen "
        "(formulierfouten, 'opgeslagen', aantallen resultaten, updates van "
        "het winkelmandje), worden die waarschijnlijk niet voorgelezen door "
        "schermlezers — controleer WCAG 4.1.3."
    ),
    "live region": "live-regio",
    "A live region ({where}) was found. Confirm the page routes its status "
    "messages (errors, 'saved', result counts) through it so they are "
    "announced without moving focus (WCAG 4.1.3).": (
        "Er is een live-regio ({where}) gevonden. Bevestig dat de pagina haar "
        "statusberichten (fouten, 'opgeslagen', aantallen resultaten) via deze "
        "regio toont, zodat ze worden voorgelezen zonder dat de focus "
        "verplaatst (WCAG 4.1.3)."
    ),
    "A password field was found (a login/authentication step). Confirm it "
    "does not rely on a cognitive function test: the browser and password "
    "managers must be able to fill or paste it, and no un-assisted "
    "memorisation or transcription is required (WCAG 3.3.8).": (
        "Er is een wachtwoordveld gevonden (een aanmeld- of "
        "authenticatiestap). Bevestig dat het niet steunt op een cognitieve "
        "functietest: de browser en wachtwoordbeheerders moeten het kunnen "
        "invullen of erin kunnen plakken, en er is geen onondersteund "
        "onthouden of overschrijven nodig (WCAG 3.3.8)."
    ),
    "A {kind} was found. Confirm an accessible alternative to the cognitive "
    "test exists (e.g. an audio challenge, an email/link sign-in, or object "
    "recognition) (WCAG 3.3.8).": (
        "Er is een {kind} gevonden. Bevestig dat er een toegankelijk "
        "alternatief voor de cognitieve test bestaat (bv. een audiotest, "
        "aanmelden via e-mail of een link, of objectherkenning) (WCAG 3.3.8)."
    ),
    "a search field": "een zoekveld",
    "site navigation": "sitenavigatie",
    "a sitemap link": "een link naar de sitemap",
    "No obvious way to locate this page was detected (no search field, site "
    "navigation, or sitemap link). WCAG 2.4.5 needs at least two independent "
    "ways to find a page — verify manually (exempt if this page is a step "
    "within a process).": (
        "Er is geen duidelijke manier gevonden om deze pagina te vinden (geen "
        "zoekveld, sitenavigatie of link naar de sitemap). WCAG 2.4.5 vereist "
        "minstens twee onafhankelijke manieren om een pagina te vinden — "
        "controleer dit handmatig (uitgezonderd als deze pagina een stap in "
        "een proces is)."
    ),
    "Ways to locate this page detected: {found}. WCAG 2.4.5 needs at least "
    "two independent ways that lead here — confirm there are two or more and "
    "each actually leads here (exempt if this page is a step within a "
    "process).": (
        "Gevonden manieren om deze pagina te vinden: {found}. WCAG 2.4.5 "
        "vereist minstens twee onafhankelijke manieren die naar deze pagina "
        "leiden — bevestig dat het er twee of meer zijn en dat elk ervan echt "
        "naar deze pagina leidt (uitgezonderd als deze pagina een stap in een "
        "proces is)."
    ),
    "Ways to locate this page detected: {found}. WCAG 2.4.5 needs at least "
    "two independent ways that lead here — confirm at least one more "
    "independent way exists (exempt if this page is a step within a "
    "process).": (
        "Gevonden manieren om deze pagina te vinden: {found}. WCAG 2.4.5 "
        "vereist minstens twee onafhankelijke manieren die naar deze pagina "
        "leiden — bevestig dat er nog minstens één andere onafhankelijke "
        "manier bestaat (uitgezonderd als deze pagina een stap in een proces "
        "is)."
    ),
    "a help/contact link": "een hulp- of contactlink",
    "Help/contact mechanism(s) found ({examples}). WCAG 3.2.6 needs help "
    "that is offered to appear in the same relative order on every page that "
    "has it — compare its placement across the audited pages.": (
        "Hulp- of contactmechanisme(n) gevonden ({examples}). WCAG 3.2.6 "
        "vereist dat aangeboden hulp op elke pagina waar ze voorkomt in "
        "dezelfde relatieve volgorde staat — vergelijk de plaats ervan op de "
        "geauditeerde pagina's."
    ),
    # --- content -------------------------------------------------------------
    "Link text {name} may not describe the link's purpose out of context "
    "(WCAG 2.4.4). Confirm the destination is clear from the link text "
    "alone, or make the text more specific.": (
        "Linktekst {name} beschrijft het linkdoel buiten de context mogelijk "
        "niet (WCAG 2.4.4). Bevestig dat de bestemming duidelijk is uit de "
        "linktekst alleen, of maak de tekst specifieker."
    ),
    "This heading has no text content — a heading must describe the section "
    "it introduces (WCAG 2.4.6). Give it descriptive text or remove it if it "
    "is not a real heading.": (
        "Deze kop heeft geen tekst — een kop moet het onderdeel beschrijven "
        "dat hij inleidt (WCAG 2.4.6). Geef hem een beschrijvende tekst of "
        "verwijder hem als het geen echte kop is."
    ),
    # --- keyboard_nav --------------------------------------------------------
    "No computed-style change detected when this element received keyboard "
    "focus — it may lack a visible focus indicator. Confirm a focus "
    "indicator is perceivable.": (
        "Er is geen wijziging in de berekende stijl gedetecteerd toen dit "
        "element de toetsenbordfocus kreeg — mogelijk ontbreekt een zichtbare "
        "focusindicator. Bevestig dat een focusindicator waarneembaar is."
    ),
    "The focused element is covered by other content at its centre point — "
    "focus may be hidden (e.g. behind a sticky header). Confirm the focused "
    "element stays visible.": (
        "Het element met focus wordt in zijn middelpunt bedekt door andere "
        "content — de focus kan verborgen zijn (bv. achter een vaste "
        "kopbalk). Bevestig dat het element met focus zichtbaar blijft."
    ),
    "Target renders at {width}×{height} CSS px, below the "
    "{minimum}×{minimum} minimum. Confirm no spacing, inline, or "
    "equivalent-control exception applies.": (
        "Het aanwijsgebied is {width}×{height} CSS-px groot, kleiner dan het "
        "minimum van {minimum}×{minimum}. Bevestig dat geen uitzondering voor "
        "tussenruimte, inline-elementen of een gelijkwaardig "
        "bedieningselement van toepassing is."
    ),
    "Positive tabindex ({tabindex}) forces this element ahead of the "
    "document order. Confirm the resulting focus order is still meaningful; "
    "prefer tabindex 0 and DOM order.": (
        "Een positieve tabindex ({tabindex}) plaatst dit element vóór de "
        "documentvolgorde. Bevestig dat de focusvolgorde die daaruit volgt "
        "nog betekenisvol is; gebruik bij voorkeur tabindex 0 en de "
        "DOM-volgorde."
    ),
    "Keyboard focus stayed on this element for {presses}+ consecutive Tab "
    "presses — focus may be trapped. Confirm focus can move away using the "
    "keyboard alone (Tab or documented keys).": (
        "De toetsenbordfocus bleef {presses} of meer keer na elkaar op dit "
        "element na een druk op Tab — de focus zit mogelijk vast. Bevestig "
        "dat de focus met alleen het toetsenbord kan worden verplaatst (Tab "
        "of gedocumenteerde toetsen)."
    ),
    # --- reflow --------------------------------------------------------------
    "At a {width} CSS-px viewport the page content is {scroll_width}px wide "
    "and scrolls horizontally (viewport {client_width}px). WCAG 1.4.10 "
    "requires content to reflow to one column with no horizontal scrolling "
    "at 320px. Confirm — content that genuinely needs a two-dimensional "
    "layout (data tables, maps) is exempt.": (
        "Bij een viewport van {width} CSS-px is de content van de pagina "
        "{scroll_width}px breed en scrolt ze horizontaal (viewport "
        "{client_width}px). WCAG 1.4.10 vereist dat content bij 320px in één "
        "kolom herschikt zonder horizontaal scrollen. Bevestig dit — content "
        "die echt een tweedimensionale lay-out nodig heeft (datatabellen, "
        "kaarten) is uitgezonderd."
    ),
}
