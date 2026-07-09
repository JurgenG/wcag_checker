"""The bulk runner's ``domains.csv`` reader.

Two accepted shapes:

* **Single column** (original) — one URL per line, no header, ``#``
  comments and blanks skipped. No per-site display name.
* **Multi-column with a header** — first non-comment row names the
  columns; a ``name`` column supplies the report title and a ``website``
  column the URL (matched by title, case-insensitive). Extra columns are
  ignored.

``_read_domains`` returns ``(url, display_name)`` pairs.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import run as bulk_run  # noqa: E402
import overview as bulk_overview  # noqa: E402

from tests.fixtures.bundles import path as bundle_path  # noqa: E402


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "domains.csv"
    p.write_text(text, encoding="utf-8")
    return p


def test_single_column_is_urls_with_no_name(tmp_path) -> None:
    """The original one-URL-per-line format still works; name is None."""
    csv = _write(tmp_path, "# a comment\nhttps://a.be\n\nhttps://www.b.be\n")
    assert bulk_run._read_domains(csv) == [
        ("https://a.be", None),
        ("https://www.b.be", None),
    ]


def test_two_columns_use_name_and_website_by_title(tmp_path) -> None:
    """A header naming name/website columns drives (url, name) pairs."""
    csv = _write(
        tmp_path,
        "name,website\n"
        "GO! Basisschool De Kleurdoos,https://www.bsdekleurdoos.be\n"
        "Abdijschool,https://www.abdijschool.be\n",
    )
    assert bulk_run._read_domains(csv) == [
        ("https://www.bsdekleurdoos.be", "GO! Basisschool De Kleurdoos"),
        ("https://www.abdijschool.be", "Abdijschool"),
    ]


def test_header_columns_matched_by_title_not_position(tmp_path) -> None:
    """Column order doesn't matter — titles are matched, not positions."""
    csv = _write(
        tmp_path,
        "website,name\nhttps://www.x.be,School X\n",
    )
    assert bulk_run._read_domains(csv) == [("https://www.x.be", "School X")]


def test_extra_columns_are_ignored(tmp_path) -> None:
    """More than two columns: only name + website are used; rest ignored."""
    csv = _write(
        tmp_path,
        "name,website,city,level\n"
        "School Y,https://www.y.be,Brussel,SO\n",
    )
    assert bulk_run._read_domains(csv) == [("https://www.y.be", "School Y")]


def test_multicolumn_skips_blank_and_comment_rows(tmp_path) -> None:
    """Comments and blank rows are skipped in the headered form too."""
    csv = _write(
        tmp_path,
        "name,website\n"
        "# skip me,https://nope.be\n"
        "\n"
        "School Z,https://www.z.be\n",
    )
    assert bulk_run._read_domains(csv) == [("https://www.z.be", "School Z")]


def test_blank_name_cell_falls_back_to_no_name(tmp_path) -> None:
    """An empty name cell yields None so the report titles itself by host."""
    csv = _write(tmp_path, "name,website\n,https://www.q.be\n")
    assert bulk_run._read_domains(csv) == [("https://www.q.be", None)]


# --- the overview agrees with the runner on slugs --------------------------
#
# The overview cross-references domains.csv against the captures on disk to
# flag URLs that never produced a bundle. It must derive slugs identically
# to the runner — otherwise a multi-column (name,website) CSV makes every
# row look like a missing capture.


def test_overview_expected_slugs_for_named_csv(tmp_path) -> None:
    """The overview reads the name,website form and yields the same hosts
    the runner captures under (not the raw 'name,url' line)."""
    csv = _write(
        tmp_path,
        "name,website\nAZ Alma,https://azalma.be\nAZ Delta,https://azdelta.be\n",
    )
    assert bulk_overview._expected_slugs_from_csv(csv) == {"azalma.be", "azdelta.be"}


def test_overview_expected_slugs_for_single_column(tmp_path) -> None:
    """The original one-URL-per-line form still maps to bare hosts."""
    csv = _write(tmp_path, "https://a.be\nhttps://www.b.be\n")
    assert bulk_overview._expected_slugs_from_csv(csv) == {"a.be", "www.b.be"}


# --- --resume re-captures previously-failed captures -----------------------


def test_prior_capture_failed_is_false_for_a_successful_bundle() -> None:
    """A healthy capture is not re-done on resume."""
    assert bulk_run._prior_capture_failed(bundle_path("aalst.zip")) is False


def test_prior_capture_failed_is_true_for_an_unreadable_bundle(tmp_path) -> None:
    """A missing / corrupt bundle counts as failed so resume re-captures it."""
    assert bulk_run._prior_capture_failed(tmp_path / "nope.zip") is True
