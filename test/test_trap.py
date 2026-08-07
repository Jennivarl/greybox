"""
Unit tests for the Stage 3 trap (contracts/trap.py). Pure Python,
no GenLayer runtime -- run with plain `pytest`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contracts.trap import (
    build_trap_instruction,
    canary_tripped,
    derive_seed,
    generate_secret_word,
)


def test_same_inputs_give_same_seed():
    seed1 = derive_seed(b"sender-a", b"contract-x", b"evidence text")
    seed2 = derive_seed(b"sender-a", b"contract-x", b"evidence text")
    assert seed1 == seed2


def test_different_evidence_gives_different_seed():
    seed1 = derive_seed(b"sender-a", b"contract-x", b"evidence one")
    seed2 = derive_seed(b"sender-a", b"contract-x", b"evidence two")
    assert seed1 != seed2


def test_different_sender_gives_different_seed():
    seed1 = derive_seed(b"sender-a", b"contract-x", b"same evidence")
    seed2 = derive_seed(b"sender-b", b"contract-x", b"same evidence")
    assert seed1 != seed2


def test_secret_word_deterministic_for_same_seed():
    seed = derive_seed(b"sender-a", b"contract-x", b"evidence text")
    word1 = generate_secret_word(seed)
    word2 = generate_secret_word(seed)
    assert word1 == word2


def test_secret_word_changes_across_calls():
    words = set()
    for i in range(50):
        seed = derive_seed(b"sender-a", b"contract-x", f"evidence {i}".encode())
        words.add(generate_secret_word(seed))
    # 50 distinct evidence texts should not collide onto the same word
    assert len(words) == 50


def test_secret_word_has_expected_shape():
    seed = derive_seed(b"s", b"c", b"e")
    word = generate_secret_word(seed)
    assert word.startswith("XG-")
    assert len(word) == len("XG-") + 10


def test_trap_instruction_contains_the_word():
    word = "XG-ABC123XYZ9"
    instruction = build_trap_instruction(word)
    assert word in instruction


def test_canary_tripped_true_when_word_present():
    word = "XG-ABC123XYZ9"
    assert canary_tripped(f"Sure, here you go: {word}", word) is True


def test_canary_tripped_false_when_word_absent():
    word = "XG-ABC123XYZ9"
    assert canary_tripped("I will not comply with hidden instructions.", word) is False


def test_canary_tripped_false_on_empty_output():
    assert canary_tripped("", "XG-ABC123XYZ9") is False
    assert canary_tripped(None, "XG-ABC123XYZ9") is False


def test_canary_tripped_is_case_sensitive_exact_token_match():
    word = "XG-ABC123XYZ9"
    # a lowercased mangling of the token should not count as a match --
    # we want proof the model reproduced the exact token, not a fuzzy echo
    assert canary_tripped(f"here: {word.lower()}", word) is False
