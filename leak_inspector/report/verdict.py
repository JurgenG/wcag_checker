"""Manager-facing verdict layer.

Builds a small set of plain-language strings on top of the existing
``Analysis``. Deterministic: same input produces byte-identical
output. No model calls, no network. Reads ``Analysis`` only; does not
mutate it.

House style for emitted strings: short sentences, dry register, no
em-dashes, no rhetorical triads, colons and parentheses for asides.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..analysis.runner import Analysis
from ..modules.base import CAT_IDENTIFIER, CAT_PII


@dataclass
class Verdict:
    """Plain-language verdict summary built from one ``Analysis``.

    Three to four sentences sized to be read in five seconds:

    * ``top_sentences[0]`` — external-connection count, with how many
      are expected infrastructure.
    * ``top_sentences[1]`` — :attr:`personal_data_line` (same string).
    * ``top_sentences[2]`` — one actionable item, or the canonical
      "Nothing requiring action was found." fallback.
    * ``top_sentences[3]`` (optional) — partial-coverage clause when
      one or more contacted vendors could not be classified.

    The fields are denormalised on purpose: callers that only want the
    personal-data line can read it directly; renderers that want the
    full verdict join ``top_sentences`` with spaces.
    """

    personal_data_line: str
    top_sentences: list[str]


#: The canonical zero-case line. Pinned exactly so downstream rendering
#: and snapshot tests can match it without ambiguity.
_NO_PERSONAL_DATA_LINE = (
    "No citizen personal data was observed leaving the website "
    "during this scan."
)


def personal_data_line(analysis: Analysis) -> str:
    """Render the personal-data line for the verdict.

    Counts **distinct** personal-data field types leaving to third-
    party trackers — deduplicated per ``(vendor, category, canonical
    key)``. The same Google Analytics ``cid`` parameter being sent
    on every beacon is one identifier leaking, not one per beacon;
    a naive sum over hit params over-counts by an order of magnitude
    on chatty trackers.

    First-party hits are excluded by design: the verdict is about
    data leaving the site, not about data the site processes on its
    own behalf.
    """
    from .builder import _canonical_key

    distinct_fields: set[tuple[str, str, str]] = set()
    tracker_names: set[str] = set()
    for hit in analysis.hits:
        if not analysis.is_third_party_host(hit.host):
            continue
        for p in hit.params:
            if p.category not in (CAT_PII, CAT_IDENTIFIER):
                continue
            distinct_fields.add(
                (hit.module_name, p.category, _canonical_key(p.key))
            )
            tracker_names.add(hit.module_name)

    field_count = len(distinct_fields)
    if field_count == 0:
        return _NO_PERSONAL_DATA_LINE

    sorted_names = sorted(tracker_names)
    tracker_count = len(sorted_names)
    noun = "tracker" if tracker_count == 1 else "trackers"
    return (
        f"{field_count} distinct personal-data field"
        f"{'s' if field_count != 1 else ''} "
        f"observed leaving via {tracker_count} {noun}: "
        f"{', '.join(sorted_names)}."
    )


def build_top_verdict_sentences(analysis: Analysis) -> list[str]:
    """Build the three-or-four sentence top verdict.

    See :class:`Verdict` for the per-sentence semantics. The list is
    always 3 sentences long, plus an optional 4th appended when at
    least one contacted vendor is ``unclassified``.
    """
    from .verdict_classification import classify_module, classify_vendor
    from .debug import collect_unknown_hosts

    # --- Sentence 1: external connections + expected count ---------------
    # "Contacted external vendors": (a) every distinct tracker module that
    # fired against a third-party host, plus (b) every distinct third-party
    # host that no module claimed. Each is one vendor.
    third_party_modules: list[str] = []
    seen_modules: set[str] = set()
    for hit in analysis.hits:
        if not analysis.is_third_party_host(hit.host):
            continue
        if hit.module_id in seen_modules:
            continue
        seen_modules.add(hit.module_id)
        third_party_modules.append(hit.module_id)

    unclassified_host_count = len(collect_unknown_hosts(analysis))
    total_vendors = len(third_party_modules) + unclassified_host_count

    expected_count = sum(
        1 for mid in third_party_modules
        if classify_module(mid).category == "expected"
    )

    if total_vendors == 0:
        s1 = "The site contacted no third-party vendors during this scan."
    elif total_vendors == 1:
        if expected_count == 1:
            s1 = "The site contacted 1 external vendor (expected infrastructure)."
        else:
            s1 = "The site contacted 1 external vendor."
    else:
        s1 = (
            f"The site contacted {total_vendors} external vendors, "
            f"{expected_count} of which "
            f"{'is' if expected_count == 1 else 'are'} "
            f"expected infrastructure."
        )

    # --- Sentence 2: personal-data line (item 1) -------------------------
    s2 = personal_data_line(analysis)

    # --- Sentence 3: highest-priority actionable, or fallback ------------
    actionable_modules = sorted(
        mid for mid in third_party_modules
        if classify_module(mid).category == "actionable"
    )
    if actionable_modules:
        verdict = classify_module(actionable_modules[0])
        # First sentence of the classifier's note. The note may be one or
        # two sentences; pick the first to keep s3 itself a single sentence.
        first_sentence = verdict.note.split(".", 1)[0].strip() + "."
        s3 = first_sentence
    else:
        s3 = "Nothing requiring action was found."

    sentences = [s1, s2, s3]

    # --- Sentence 4 (optional): partial-coverage append ------------------
    # Count vendors whose classification is "unclassified": untracked third-
    # party hosts (no module fired) AND any module that's not in the seed
    # mapping. The latter shouldn't usually exist on real captures yet, but
    # the rule is "honestly partial."
    unclassified_modules = sum(
        1 for mid in third_party_modules
        if classify_module(mid).category == "unclassified"
    )
    total_unclassified = unclassified_host_count + unclassified_modules
    if total_unclassified > 0:
        s4 = (
            f"{total_unclassified} vendor"
            f"{'s' if total_unclassified != 1 else ''} "
            f"could not be classified."
        )
        sentences.append(s4)

    return sentences


def build_verdict(analysis: Analysis) -> Verdict:
    """Build a :class:`Verdict` for ``analysis``.

    Pure: depends only on ``Analysis`` fields. Same input → identical
    Verdict. Composed of the individual line builders so each can be
    unit-tested in isolation.
    """
    return Verdict(
        personal_data_line=personal_data_line(analysis),
        top_sentences=build_top_verdict_sentences(analysis),
    )


__all__ = [
    "Verdict",
    "build_top_verdict_sentences",
    "build_verdict",
    "personal_data_line",
]
