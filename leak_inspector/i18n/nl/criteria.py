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

"""Official Dutch titles of the WCAG 2.2 success criteria.

Taken verbatim from the W3C Authorized Translation of WCAG 2.2 in Dutch,
*Richtlijnen voor Toegankelijkheid van Webcontent (WCAG) 2.2*
(https://www.w3.org/Translations/WCAG22-nl/), keyed by criterion id.
"""

CRITERION_NAMES: dict[str, str] = {
    "1.1.1": "Niet-tekstuele content",
    "1.2.1": "Louter-geluid en louter-videobeeld (vooraf opgenomen)",
    "1.2.2": "Ondertitels voor doven en slechthorenden (vooraf opgenomen)",
    "1.2.3": "Audiodescriptie of media-alternatief (vooraf opgenomen)",
    "1.2.4": "Ondertitels voor doven en slechthorenden (live)",
    "1.2.5": "Audiodescriptie (vooraf opgenomen)",
    "1.2.6": "Gebarentaal (vooraf opgenomen)",
    "1.2.7": "Verlengde audiodescriptie (vooraf opgenomen)",
    "1.2.8": "Media-alternatief (vooraf opgenomen)",
    "1.2.9": "Louter-geluid (live)",
    "1.3.1": "Info en relaties",
    "1.3.2": "Betekenisvolle volgorde",
    "1.3.3": "Zintuiglijke eigenschappen",
    "1.3.4": "Weergavestand",
    "1.3.5": "Identificeer het doel van de input",
    "1.3.6": "Identificeer het doel",
    "1.4.1": "Gebruik van kleur",
    "1.4.2": "Geluidsbediening",
    "1.4.3": "Contrast (minimum)",
    "1.4.4": "Herschalen van tekst",
    "1.4.5": "Afbeeldingen van tekst",
    "1.4.6": "Contrast (versterkt)",
    "1.4.7": "Weinig of geen achtergrondgeluid",
    "1.4.8": "Visuele weergave",
    "1.4.9": "Afbeeldingen van tekst (geen uitzondering)",
    "1.4.10": "Reflow",
    "1.4.11": "Contrast van niet-tekstuele content",
    "1.4.12": "Tekstafstand",
    "1.4.13": "Content bij hover of focus",
    "2.1.1": "Toetsenbord",
    "2.1.2": "Geen toetsenbordval",
    "2.1.3": "Toetsenbord (geen uitzondering)",
    "2.1.4": "Enkel teken sneltoetsen",
    "2.2.1": "Timing aanpasbaar",
    "2.2.2": "Pauzeren, stoppen, verbergen",
    "2.2.3": "Geen timing",
    "2.2.4": "Onderbrekingen",
    "2.2.5": "Herauthentisering",
    "2.2.6": "Time-outs",
    "2.3.1": "Drie flitsen of beneden drempelwaarde",
    "2.3.2": "Drie flitsen",
    "2.3.3": "Animatie uit interacties",
    "2.4.1": "Blokken omzeilen",
    "2.4.2": "Paginatitel",
    "2.4.3": "Focus volgorde",
    "2.4.4": "Linkdoel (in context)",
    "2.4.5": "Meerdere manieren",
    "2.4.6": "Koppen en labels",
    "2.4.7": "Focus zichtbaar",
    "2.4.8": "Locatie",
    "2.4.9": "Linkdoel (alleen link)",
    "2.4.10": "Paragraafkoppen",
    "2.4.11": "Focus niet bedekt (minimum)",
    "2.4.12": "Focus niet bedekt (uitgebreid)",
    "2.4.13": "Focusweergave",
    "2.5.1": "Aanwijzergebaren",
    "2.5.2": "Aanwijzerannulering",
    "2.5.3": "Label in naam",
    "2.5.4": "Bewegingsactivering",
    "2.5.5": "Grootte van het aanwijsgebied (uitgebreid)",
    "2.5.6": "Input gelijktijdige invoermechanismen",
    "2.5.7": "Sleepbewegingen",
    "2.5.8": "Grootte van het aanwijsgebied (minimum)",
    "3.1.1": "Taal van de pagina",
    "3.1.2": "Taal van onderdelen",
    "3.1.3": "Ongebruikelijke woorden",
    "3.1.4": "Afkortingen",
    "3.1.5": "Leesniveau",
    "3.1.6": "Uitspraak",
    "3.2.1": "Bij focus",
    "3.2.2": "Bij input",
    "3.2.3": "Consistente navigatie",
    "3.2.4": "Consistente identificatie",
    "3.2.5": "Verandering op verzoek",
    "3.2.6": "Consistente hulp",
    "3.3.1": "Foutidentificatie",
    "3.3.2": "Labels of instructies",
    "3.3.3": "Foutsuggestie",
    "3.3.4": "Foutpreventie (wettelijk, financieel, gegevens)",
    "3.3.5": "Hulp",
    "3.3.6": "Foutpreventie (alle)",
    "3.3.7": "Overbodige invoer",
    "3.3.8": "Toegankelijke authenticatie (minimum)",
    "3.3.9": "Toegankelijke authenticatie (uitgebreid)",
    "4.1.2": "Naam, rol, waarde",
    "4.1.3": "Statusberichten",
}
