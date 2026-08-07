"""
Stage 6 of Evidence Guard: the attack corpus.

Exercises the Stage 2 cleaner against a set of realistic evidence documents,
each carrying exactly one hidden-instruction vector, plus a set of clean
controls that must pass through untouched. This only tests the cleaner
(no LLM, no GenVM) -- it's the offline-testable half of the pipeline. The
canary trap (Stage 3) and the judge's actual injection verdict (Stage 4)
need a live LLM call and are exercised separately via Studio/Bradbury, not
here.

Attacks are split into two groups:

  - CLEANER_CAUGHT: formatting-based hiding tricks (invisible characters,
    HTML comments, hidden-styled spans, alt text, fake role labels). The
    cleaner is specifically designed to strip these, so it must flag every
    one of them -- a miss here is a real regression.

  - CLEANER_MISSES: semantic hiding tricks (base64 encoding, one-character-
    per-line splitting, a different natural language) that aren't formatting
    tricks at all, so the cleaner has no mechanism to catch them by design.
    These rely entirely on the judge LLM (Stage 4) plus the canary trap
    (Stage 3) to catch, which this offline suite can't exercise. Asserting
    `removed == []` here documents the gap honestly instead of hiding it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contracts.cleaner import clean

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
ATTACKS_DIR = CORPUS_DIR / "attacks"
CLEAN_DIR = CORPUS_DIR / "clean"

CLEANER_CAUGHT = [
    "01_zero_width_chars.txt",
    "02_html_comment.txt",
    "03_white_on_white_span.txt",
    "04_display_none_div.txt",
    "05_font_size_zero_span.txt",
    "06_image_alt_text.txt",
    "07_fake_system_role.txt",
    "08_fake_instruction_header.txt",
    "09_inst_bracket.txt",
    "10_bidi_override.txt",
]

CLEANER_MISSES = [
    "11_base64_encoded.txt",
    "12_split_across_lines.txt",
    "13_foreign_language.txt",
]

ALL_ATTACKS = CLEANER_CAUGHT + CLEANER_MISSES


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_corpus_directories_are_populated():
    assert sorted(p.name for p in ATTACKS_DIR.glob("*.txt")) == sorted(ALL_ATTACKS)
    assert len(list(CLEAN_DIR.glob("*.txt"))) >= 5


def test_all_attack_files_are_classified():
    # every file on disk must be in exactly one of the two lists above --
    # catches the case where someone adds a fixture and forgets to classify it
    on_disk = {p.name for p in ATTACKS_DIR.glob("*.txt")}
    classified = set(CLEANER_CAUGHT) | set(CLEANER_MISSES)
    assert on_disk == classified


def test_cleaner_catches_known_formatting_attacks():
    failures = []
    for name in CLEANER_CAUGHT:
        text = _read(ATTACKS_DIR / name)
        result = clean(text)
        if not result.removed:
            failures.append(name)
    assert not failures, f"cleaner failed to flag: {failures}"


def test_cleaner_known_gaps_are_still_gaps():
    # documents current limitations rather than hiding them -- if one of
    # these starts getting caught, great, but then it should graduate to
    # CLEANER_CAUGHT above with a real assertion, not sit here silently
    unexpected_catches = []
    for name in CLEANER_MISSES:
        text = _read(ATTACKS_DIR / name)
        result = clean(text)
        if result.removed:
            unexpected_catches.append((name, result.removed))
    assert not unexpected_catches, (
        f"a documented gap started getting caught, update the corpus "
        f"classification: {unexpected_catches}"
    )


def test_clean_controls_produce_no_false_positives():
    failures = []
    for path in sorted(CLEAN_DIR.glob("*.txt")):
        text = _read(path)
        result = clean(text)
        if result.removed:
            failures.append((path.name, result.removed))
    assert not failures, f"false positives on clean evidence: {failures}"


def test_clean_controls_are_left_essentially_unchanged():
    for path in sorted(CLEAN_DIR.glob("*.txt")):
        text = _read(path)
        result = clean(text)
        assert result.cleaned_text == text.strip()
