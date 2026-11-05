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

"""Dutch translations: command-line help and terminal messages."""

MESSAGES: dict[str, str] = {
    # -- cli: wcag-checker --------------------------------------------------
    (
        "Open Firefox on a URL and audit it for WCAG 2.2 AA issues. By "
        "default you browse by hand and press the audit hotkey on each page "
        "to audit; with --once the given page is audited automatically and "
        "the tool exits. A clean run is not a conformance claim."
    ): (
        "Open Firefox op een URL en audit de pagina's op problemen met WCAG "
        "2.2 AA. Standaard surf je zelf en druk je op elke te auditen pagina "
        "op de audit-sneltoets; met --once wordt de opgegeven pagina "
        "automatisch geaudit en stopt het programma. Een run zonder "
        "bevindingen is geen conformiteitsclaim."
    ),
    "starting URL to open (include the scheme)": (
        "start-URL om te openen (inclusief het schema, bv. https://)"
    ),
    "directory for the reports (default: reports/)": (
        "map voor de rapporten (standaard: reports/)"
    ),
    "run Firefox without a visible window (a real desktop is preferred)": (
        "Firefox zonder zichtbaar venster uitvoeren (een echt bureaublad "
        "verdient de voorkeur)"
    ),
    (
        "resize the browser window to this pixel width before auditing, to "
        "check a responsive/mobile layout (default: Firefox's own window "
        "width)"
    ): (
        "het browservenster vóór de audit op deze breedte in pixels zetten, "
        "om een responsieve/mobiele opmaak te controleren (standaard: de "
        "eigen vensterbreedte van Firefox)"
    ),
    (
        "audit the given page once and exit, without the interactive hotkey "
        "(waits for the page to settle first — use this when a page "
        "redirects or closes too fast to press the hotkey)"
    ): (
        "de opgegeven pagina één keer auditen en stoppen, zonder interactieve "
        "sneltoets (wacht eerst tot de pagina volledig geladen is — gebruik "
        "dit als een pagina te snel doorverwijst of sluit om de sneltoets in "
        "te drukken)"
    ),
    (
        "interactive audit hotkey, e.g. ctrl+alt+shift+a or f9 (default: "
        "%(default)s). Change it if your window manager grabs the default "
        "combo."
    ): (
        "sneltoets voor een interactieve audit, bv. ctrl+alt+shift+a of f9 "
        "(standaard: %(default)s). Wijzig hem als je systeem de standaardtoets "
        "al gebruikt."
    ),
    (
        "report format(s), comma-separated — choose from {choices} (default: "
        "%(default)s). 'jira-tickets' writes one JIRA-style ticket per issue "
        "type into a jira/ subfolder; 'all' writes every format. The "
        "manual-review checklist is always written."
    ): (
        "rapportformaat of -formaten, gescheiden door komma's — kies uit "
        "{choices} (standaard: %(default)s). 'jira-tickets' schrijft één "
        "ticket in JIRA-stijl per soort probleem in een submap jira/; 'all' "
        "schrijft alle formaten. De checklist voor handmatige controle wordt "
        "altijd geschreven."
    ),
    "language of the reports and messages: {choices} (default: %(default)s)": (
        "taal van de rapporten en meldingen: {choices} (standaard: %(default)s)"
    ),
    "Invalid --format {value}: {reason}": "Ongeldige --format {value}: {reason}",
    "Invalid --width {value}: must be a positive number of pixels": (
        "Ongeldige --width {value}: moet een positief aantal pixels zijn"
    ),
    "Invalid --hotkey {value}: {reason}": "Ongeldige --hotkey {value}: {reason}",
    (
        "Opening Firefox. Browse to a page you want checked, click into the "
        "page (so it has keyboard focus), then press {combo} to audit it. "
        "Each audit is confirmed below. Close the window when you're done."
    ): (
        "Firefox wordt geopend. Ga naar een pagina die je wilt laten "
        "controleren, klik in de pagina (zodat ze de toetsenbordfocus heeft) "
        "en druk op {combo} om ze te auditen. Elke audit wordt hieronder "
        "bevestigd. Sluit het venster als je klaar bent."
    ),
    "audited {url} — {count} finding(s)": "geauditeerd: {url} — {count} bevinding(en)",
    "Audited {pages} page(s); {count} finding(s).": (
        "{pages} pagina('s) geauditeerd; {count} bevinding(en)."
    ),
    "Opening Firefox and auditing {url} once...": (
        "Firefox wordt geopend en {url} wordt één keer geaudit..."
    ),
    "Note: {url} redirected to {target}; audited that.": (
        "Let op: {url} verwees door naar {target}; die pagina is geaudit."
    ),
    "Audited {url}; {count} finding(s).": "{url} geauditeerd; {count} bevinding(en).",
    "Reports written to {path}/": "Rapporten geschreven naar {path}/",
    "JIRA tickets": "JIRA-tickets",
    "Reminder: a clean automated run does not imply WCAG 2.2 conformance.": (
        "Ter herinnering: een geautomatiseerde run zonder bevindingen betekent "
        "geen conformiteit met WCAG 2.2."
    ),
    # -- cli_batch: wcag-batch ----------------------------------------------
    (
        "Audit every URL in a list file for WCAG 2.2 AA issues, one report "
        "directory per site plus an aggregate summary. A clean run is not a "
        "conformance claim."
    ): (
        "Audit elke URL uit een lijstbestand op problemen met WCAG 2.2 AA, met "
        "één rapportmap per site en een overkoepelende samenvatting. Een run "
        "zonder bevindingen is geen conformiteitsclaim."
    ),
    (
        "text file with one URL per line, or name,url pairs (# comments and "
        "blanks ignored)"
    ): (
        "tekstbestand met één URL per regel, of paren naam,url (regels met # "
        "en lege regels worden overgeslagen)"
    ),
    "directory for the per-site reports + summary (default: runs/)": (
        "map voor de rapporten per site en de samenvatting (standaard: runs/)"
    ),
    "audit only the first N URLs (default: all)": (
        "alleen de eerste N URL's auditen (standaard: alle)"
    ),
    "run Firefox hidden (focus/keyboard checks are less reliable)": (
        "Firefox verborgen uitvoeren (focus- en toetsenbordcontroles zijn dan "
        "minder betrouwbaar)"
    ),
    (
        "resize the browser window to this pixel width before auditing every "
        "site, to check responsive/mobile layouts (default: Firefox's own "
        "window width)"
    ): (
        "het browservenster vóór de audit van elke site op deze breedte in "
        "pixels zetten, om responsieve/mobiele opmaak te controleren "
        "(standaard: de eigen vensterbreedte van Firefox)"
    ),
    (
        "per-site report format(s), comma-separated — choose from {choices} "
        "(default: %(default)s). 'jira-tickets' writes one ticket per issue "
        "type per site into that site's jira/ subfolder."
    ): (
        "rapportformaat of -formaten per site, gescheiden door komma's — kies "
        "uit {choices} (standaard: %(default)s). 'jira-tickets' schrijft één "
        "ticket per soort probleem per site in de submap jira/ van die site."
    ),
    "Auditing {planned} of {total} URL(s) from {source}...": (
        "{planned} van {total} URL('s) uit {source} worden geaudit..."
    ),
    "Done: {audited} audited, {failed} failed.": (
        "Klaar: {audited} geauditeerd, {failed} mislukt."
    ),
    "Summary + per-site reports written to {path}/": (
        "Samenvatting en rapporten per site geschreven naar {path}/"
    ),
    # -- capture.driver: Firefox launch ---------------------------------------
    (
        "Firefox not found — downloading a private copy for capture (~80 MB, "
        "one-time). This may take a minute…"
    ): (
        "Firefox niet gevonden — er wordt een eigen exemplaar gedownload "
        "(~80 MB, eenmalig). Dit kan een minuut duren…"
    ),
    (
        "Firefox is not installed and could not be downloaded ({error}). "
        "Install Firefox manually, or run on a machine with network access "
        "for the one-time ~80 MB fetch."
    ): (
        "Firefox is niet geïnstalleerd en kon niet worden gedownload "
        "({error}). Installeer Firefox zelf, of gebruik een computer met "
        "internettoegang voor de eenmalige download van ~80 MB."
    ),
    (
        "Requested browser width {width}px but Firefox used {achieved}px (it "
        "enforces a minimum window width). The page was audited at "
        "{achieved}px, not {width}px — narrower mobile layouts cannot be "
        "reproduced this way."
    ): (
        "Gevraagde browserbreedte {width}px, maar Firefox gebruikte "
        "{achieved}px (het hanteert een minimale vensterbreedte). De pagina "
        "is geaudit op {achieved}px, niet op {width}px — smallere mobiele "
        "opmaak kan op deze manier niet worden nagebootst."
    ),
}
