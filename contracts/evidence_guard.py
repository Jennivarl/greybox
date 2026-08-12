# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
Stage 5: GREYBOX, the Intelligent Contract wrapper.

Other contracts import this one, hand it evidence, and get back a verdict on
whether that evidence contains hidden instructions aimed at whatever LLM
reads it next -- optionally with a permanent, provable on-chain record.

Three independent signals feed one verdict, in descending order of
certainty:

  1. What the deterministic cleaner had to remove. Content deliberately
     made invisible to a human reader settles the question outright, with
     no model involved. This binding is the point: stripping an attack and
     then asking a model to judge the sanitized leftovers would hide the
     strongest evidence the contract has.
  2. Whether the canary leaked. A model that obeys an instruction planted
     in text it was handed as data cannot be trusted to screen that same
     submission, so the result fails closed.
  3. The model's own reading of the cleaned evidence, which stands alone
     only when neither of the above fires.

This file needs the GenVM runtime to execute (it imports `genlayer`, which
only exists inside that runtime) so it isn't unit-tested directly. The parts
that matter for correctness -- the cleaner, the trap, and the prompt,
response, and verdict-combination logic -- live in cleaner.py, trap.py, and
judge.py and are covered by their own tests plus test/test_screening.py,
which exercises the full pipeline end to end against a stubbed model.
"""

import hashlib
from dataclasses import dataclass

from genlayer import *

from contracts.cleaner import advisory_removals, clean, conclusive_removals
from contracts.judge import (
    build_canary_prompt,
    build_detection_prompt,
    combine_verdict,
    parse_judge_response,
)
from contracts.trap import canary_tripped, derive_seed, generate_secret_word


@allow_storage
@dataclass
class GuardRecord:
    injection_detected: bool
    canary_tripped: bool
    conclusive_tampering: bool
    category: str
    evidence_hash: str
    removed_items: DynArray[str]
    submitted_by: Address


class EvidenceGuard(gl.Contract):
    records: TreeMap[str, GuardRecord]

    def __init__(self):
        pass

    def _seed_material(self, evidence: str) -> tuple:
        msg = gl.message
        return (
            msg.sender_address.as_hex.encode(),
            msg.contract_address.as_hex.encode(),
            str(msg.chain_id).encode(),
            evidence.encode("utf-8"),
        )

    def _screen(self, evidence: str) -> GuardRecord:
        cleaned = clean(evidence)
        conclusive = conclusive_removals(cleaned.removed)
        advisory = advisory_removals(cleaned.removed)

        seed = derive_seed(*self._seed_material(cleaned.cleaned_text))
        secret_word = generate_secret_word(seed)
        detection_prompt = build_detection_prompt(cleaned.cleaned_text, advisory)
        canary_prompt = build_canary_prompt(cleaned.cleaned_text, secret_word)

        def leader_fn():
            detection_raw = gl.nondet.exec_prompt(
                detection_prompt, response_format="json"
            )
            detection = parse_judge_response(detection_raw)
            canary_raw = gl.nondet.exec_prompt(canary_prompt)
            leaked = canary_tripped(canary_raw, secret_word)
            return {
                "injection_detected": detection.injection_detected,
                "category": detection.category,
                "canary_leaked": leaked,
            }

        def validator_fn(leaders_res) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return False
            my_result = leader_fn()
            return (
                my_result["injection_detected"]
                == leaders_res.calldata["injection_detected"]
                and my_result["canary_leaked"]
                == leaders_res.calldata["canary_leaked"]
            )

        result = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        verdict = combine_verdict(
            result["injection_detected"],
            result["category"],
            result["canary_leaked"],
            conclusive,
            cleaned.removed,
        )

        evidence_hash = "0x" + hashlib.sha256(
            cleaned.cleaned_text.encode("utf-8")
        ).hexdigest()

        return GuardRecord(
            injection_detected=verdict.injection_detected,
            canary_tripped=verdict.canary_tripped,
            conclusive_tampering=verdict.conclusive_tampering,
            category=verdict.category,
            evidence_hash=evidence_hash,
            removed_items=cleaned.removed,
            submitted_by=gl.message.sender_address,
        )

    @gl.public.write
    def check(self, evidence: str) -> dict:
        """
        Screen evidence and return the verdict without storing anything.
        For callers who just want an answer, not a permanent record.
        """
        record = self._screen(evidence)
        return {
            "injection_detected": record.injection_detected,
            "canary_tripped": record.canary_tripped,
            "conclusive_tampering": record.conclusive_tampering,
            "category": record.category,
            "evidence_hash": record.evidence_hash,
            "removed_items": list(record.removed_items),
        }

    @gl.public.write
    def screen_and_record(self, evidence_id: str, evidence: str) -> dict:
        """
        Screen evidence and store the verdict under `evidence_id` so it can
        be proven later by anyone querying this contract -- the reason this
        belongs on GenLayer rather than a normal server.
        """
        if evidence_id in self.records:
            raise gl.vm.UserError(f"Evidence '{evidence_id}' already screened")

        record = self._screen(evidence)
        self.records[evidence_id] = record

        return {
            "injection_detected": record.injection_detected,
            "canary_tripped": record.canary_tripped,
            "conclusive_tampering": record.conclusive_tampering,
            "category": record.category,
            "evidence_hash": record.evidence_hash,
            "removed_items": list(record.removed_items),
        }

    @gl.public.view
    def get_record(self, evidence_id: str) -> dict:
        record = self.records[evidence_id]
        return {
            "injection_detected": record.injection_detected,
            "canary_tripped": record.canary_tripped,
            "conclusive_tampering": record.conclusive_tampering,
            "category": record.category,
            "evidence_hash": record.evidence_hash,
            "removed_items": list(record.removed_items),
            "submitted_by": record.submitted_by.as_hex,
        }
