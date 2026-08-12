"""
End-to-end tests for the full screening pipeline: clean -> classify
removals -> detection call -> canary call -> combined verdict.

This file exists because its absence hid two real bugs. Every other test
checked one stage in isolation, so nothing caught that the pipeline as a
whole produced the wrong answer:

  * A white-on-white injection was stripped by the cleaner, the model was
    then handed pristine text, correctly reported no injection, and the
    contract returned a clean verdict on an obviously tampered document.
    The removal signal was collected and then dropped on the floor.
  * The trap was planted inside the evidence the model was asked to
    screen, so a model doing its job right reported an instruction
    attempt on every submission, including clean ones.

The model is stubbed here rather than mocked at the GenVM layer, because
what needs testing is the contract's own logic around the model, not the
model itself. Each test pins the verdict for one combination of the three
signals.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contracts.cleaner import advisory_removals, clean, conclusive_removals
from contracts.judge import (
    build_canary_prompt,
    build_detection_prompt,
    combine_verdict,
)
from contracts.trap import canary_tripped, derive_seed, generate_secret_word

CORPUS = Path(__file__).resolve().parent / "corpus"


def screen(evidence: str, model_says_injected: bool = False, model_leaks_canary: bool = False):
    """
    Run the same sequence the contract runs, with a stubbed model whose
    behaviour each test controls.
    """
    cleaned = clean(evidence)
    conclusive = conclusive_removals(cleaned.removed)
    advisory = advisory_removals(cleaned.removed)

    seed = derive_seed(b"sender", b"contract", b"4221", cleaned.cleaned_text.encode())
    secret_word = generate_secret_word(seed)

    # Built for real so a broken prompt fails here too, not just in the
    # dedicated prompt tests.
    detection_prompt = build_detection_prompt(cleaned.cleaned_text, advisory)
    canary_prompt = build_canary_prompt(cleaned.cleaned_text, secret_word)
    assert secret_word not in detection_prompt
    assert secret_word in canary_prompt

    canary_response = f"Here you go: {secret_word}" if model_leaks_canary else "A summary."
    leaked = canary_tripped(canary_response, secret_word)

    return combine_verdict(
        model_says_injected,
        "hidden_instruction" if model_says_injected else "none",
        leaked,
        conclusive,
        cleaned.removed,
    )


def test_clean_evidence_with_cooperative_model_is_not_flagged():
    verdict = screen("The invoice total was $500, due on the 30th.")
    assert verdict.injection_detected is False
    assert verdict.category == "none"
    assert verdict.conclusive_tampering is False
    assert verdict.canary_tripped is False


def test_hidden_styled_attack_is_flagged_even_when_model_sees_nothing():
    """
    The core regression. The cleaner strips the hidden span, so the model
    is handed clean text and says "no injection" -- and the verdict must
    still be flagged, on the strength of the removal alone.
    """
    evidence = (CORPUS / "attacks" / "03_white_on_white_span.txt").read_text(
        encoding="utf-8"
    )
    verdict = screen(evidence, model_says_injected=False)
    assert verdict.injection_detected is True
    assert verdict.conclusive_tampering is True
    assert verdict.category == "hidden_content_removed"


def test_zero_width_attack_is_flagged_without_the_model():
    evidence = (CORPUS / "attacks" / "01_zero_width_chars.txt").read_text(
        encoding="utf-8"
    )
    verdict = screen(evidence, model_says_injected=False)
    assert verdict.injection_detected is True
    assert verdict.conclusive_tampering is True


def test_bidi_override_attack_is_flagged_without_the_model():
    evidence = (CORPUS / "attacks" / "10_bidi_override.txt").read_text(encoding="utf-8")
    verdict = screen(evidence, model_says_injected=False)
    assert verdict.injection_detected is True
    assert verdict.conclusive_tampering is True


def test_model_can_still_flag_what_the_cleaner_cannot_see():
    """
    Semantic attacks (another language, base64) leave no formatting trace,
    so the cleaner removes nothing and the model's own reading is the only
    signal. That path must still work.
    """
    evidence = (CORPUS / "attacks" / "13_foreign_language.txt").read_text(
        encoding="utf-8"
    )
    verdict = screen(evidence, model_says_injected=True)
    assert verdict.injection_detected is True
    assert verdict.conclusive_tampering is False
    assert verdict.category == "hidden_instruction"


def test_leaked_canary_fails_closed_and_is_reported_as_unreliable():
    """
    A model that obeyed the planted instruction cannot be trusted to have
    screened this submission properly, so the verdict fails closed. The
    category must say the judge was unreliable rather than claim the
    evidence was tampered with, which is a different fact.
    """
    verdict = screen("An ordinary invoice.", model_says_injected=False, model_leaks_canary=True)
    assert verdict.injection_detected is True
    assert verdict.canary_tripped is True
    assert verdict.category == "judge_unreliable"
    assert verdict.conclusive_tampering is False


def test_conclusive_removal_outranks_a_leaked_canary_in_the_category():
    evidence = (CORPUS / "attacks" / "03_white_on_white_span.txt").read_text(
        encoding="utf-8"
    )
    verdict = screen(evidence, model_leaks_canary=True)
    assert verdict.injection_detected is True
    assert verdict.category == "hidden_content_removed"
    # Still reported, just not the headline reason.
    assert verdict.canary_tripped is True


def test_advisory_removal_alone_does_not_force_a_flag():
    """
    An HTML comment is not proof of anything on its own -- the corpus
    includes a legitimate editorial one. It is passed to the model as
    context, and the model's answer decides.
    """
    evidence = (CORPUS / "clean" / "06_form_instructions_header.txt").read_text(
        encoding="utf-8"
    )
    verdict = screen(evidence, model_says_injected=False)
    assert verdict.conclusive_tampering is False
    assert verdict.injection_detected is False


def test_every_clean_control_passes_when_the_model_cooperates():
    for path in sorted((CORPUS / "clean").glob("*.txt")):
        verdict = screen(path.read_text(encoding="utf-8"), model_says_injected=False)
        assert verdict.injection_detected is False, f"false positive on {path.name}"
        assert verdict.conclusive_tampering is False, f"false positive on {path.name}"


def test_every_formatting_attack_is_caught_without_any_model_help():
    """
    The attacks that hide content in formatting must all be caught by the
    deterministic layer alone, with the model actively unhelpful.
    """
    formatting_attacks = [
        "01_zero_width_chars.txt",
        "03_white_on_white_span.txt",
        "04_display_none_div.txt",
        "05_font_size_zero_span.txt",
        "10_bidi_override.txt",
    ]
    for name in formatting_attacks:
        evidence = (CORPUS / "attacks" / name).read_text(encoding="utf-8")
        verdict = screen(evidence, model_says_injected=False)
        assert verdict.injection_detected is True, f"missed {name}"
        assert verdict.conclusive_tampering is True, f"not conclusive for {name}"
