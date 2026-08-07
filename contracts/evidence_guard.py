# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
Stage 5: EvidenceGuard, the Intelligent Contract wrapper.

Other contracts import this one, hand it evidence, and get back a verdict on
whether that evidence contains hidden instructions aimed at whatever LLM
reads it next -- optionally with a permanent, provable on-chain record.

This file needs the GenVM runtime to execute (it imports `genlayer`, which
only exists inside that runtime) so it isn't unit-tested directly. The parts
that matter for correctness -- the cleaner, the trap, and the prompt/response
handling -- live in cleaner.py, trap.py, and judge.py and are fully covered
by test/test_cleaner.py, test/test_trap.py, and test/test_judge.py. This
file is thin wiring on top of those, verified against the GenLayer docs'
current API (gl.nondet.exec_prompt, gl.vm.run_nondet_unsafe, TreeMap,
@allow_storage) but not yet exercised against a live GenVM -- do that via
Studio before deploying to Bradbury.
"""

import hashlib
from dataclasses import dataclass

from genlayer import *

from contracts.cleaner import clean
from contracts.judge import build_judge_prompt, parse_judge_response
from contracts.trap import derive_seed, generate_secret_word


@allow_storage
@dataclass
class GuardRecord:
    injection_detected: bool
    canary_tripped: bool
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
        seed = derive_seed(*self._seed_material(cleaned.cleaned_text))
        secret_word = generate_secret_word(seed)
        prompt = build_judge_prompt(cleaned.cleaned_text, secret_word)

        def leader_fn():
            raw = gl.nondet.exec_prompt(prompt, response_format="json")
            verdict = parse_judge_response(raw, secret_word)
            return {
                "injection_detected": verdict.injection_detected,
                "canary_tripped": verdict.canary_tripped,
                "category": verdict.category,
            }

        def validator_fn(leaders_res) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return False
            my_result = leader_fn()
            return (
                my_result["injection_detected"]
                == leaders_res.calldata["injection_detected"]
                and my_result["canary_tripped"]
                == leaders_res.calldata["canary_tripped"]
            )

        result = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        evidence_hash = "0x" + hashlib.sha256(
            cleaned.cleaned_text.encode("utf-8")
        ).hexdigest()

        return GuardRecord(
            injection_detected=result["injection_detected"],
            canary_tripped=result["canary_tripped"],
            category=result["category"],
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
            raise Exception(f"Evidence '{evidence_id}' already screened")

        record = self._screen(evidence)
        self.records[evidence_id] = record

        return {
            "injection_detected": record.injection_detected,
            "canary_tripped": record.canary_tripped,
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
            "category": record.category,
            "evidence_hash": record.evidence_hash,
            "removed_items": list(record.removed_items),
            "submitted_by": record.submitted_by.as_hex,
        }
