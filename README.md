# Evidence Guard

**Any GenLayer contract that reads text or images written by the parties it judges can be manipulated by them. Evidence Guard stops that.**

Evidence Guard is a Python Intelligent Contract on GenLayer. It screens evidence for hidden instructions, a form of prompt injection, before an AI judge contract ever reads that evidence. Other contracts import it, hand it raw evidence, and get back a verdict they can trust. Optionally, that verdict is written to chain as a permanent, provable record.

## Why this belongs on GenLayer

Evidence Guard does not decide whether a piece of evidence is factually true. It decides whether the evidence itself has been tampered with in a way meant to manipulate whatever AI reads it next. That is a property of the text itself, so there is no external fact to fetch or verify against.

What still requires consensus is trust in the judgment. No single validator's language model should be trusted alone, because a single fooled or compromised model is exactly the failure this contract exists to catch. Multiple independent validators must reach agreement before a verdict is accepted. When `screen_and_record()` is called, that agreed verdict is written to chain permanently, so any other contract can rely on it later without repeating the check itself. An off-chain API wrapping a single model call cannot offer either guarantee.

## How it works

Evidence passes through four stages before a verdict is produced.

**1. The cleaner.** Plain Python, no language model involved. It strips known hiding tricks from the evidence text: invisible Unicode characters, HTML comments, white-on-white or hidden CSS spans, image alt text used as a smuggling channel, and fake role labels such as `SYSTEM:` or `[INST]`. It returns both the cleaned text and a list of what it removed. That list is itself a signal: evidence that trips several of these checks is more suspicious than evidence that trips none.

**2. The trap.** Before the cleaned evidence reaches the language model, a fake instruction is planted inside it, ordering the model to reply with a specific secret word. The word is derived deterministically from the sender, the contract, the chain, and the evidence text itself, so every validator independently arrives at the same word and can check their own model's response for it. If the word appears anywhere in the model's output, that is direct proof the model followed an instruction embedded in the evidence rather than treating it purely as data. This forces the injection verdict to true regardless of anything else the model said.

**3. The judge call.** The cleaned evidence, with the trap embedded, is sent to the language model with instructions to return a structured verdict: whether an injection attempt was found, and a short category label. Validators compare only the meaningful fields of that verdict rather than requiring an exact text match, since free-text reasoning is expected to vary between models.

**4. The contract.** Everything above is wired into a GenLayer Intelligent Contract with two ways to use it. `check()` returns a verdict without storing anything, for callers who just want an answer. `screen_and_record()` does the same but also stores the result permanently under an evidence ID, so the proof can be checked by anyone later.

## Status

All seven build stages are complete, tested, and confirmed working on live GenLayer infrastructure.

| Stage | What it is | Status |
|-------|------------|--------|
| 1 | Project scaffolding | Done |
| 2 | The cleaner | Done, unit tested |
| 3 | The trap | Done, unit tested |
| 4 | The judge call | Done, unit tested |
| 5 | The contract wrapper | Done |
| 6 | The attack corpus | Done, 13 attacks and 6 clean documents |
| 7 | Deployment | Done, confirmed end to end on Studio and testnet Bradbury |

The deployed contract on Bradbury is at [`0xB68e26E21515c72Fa6a8EA3DD4df58a4bEED6db5`](https://explorer-bradbury.genlayer.com/address/0xB68e26E21515c72Fa6a8EA3DD4df58a4bEED6db5). A live `check()` call against it completed successfully: the cleaner ran, the trap was planted, the judge language model was called through consensus, and validators agreed on the verdict.

The contract also passes `genvm-lint check` with zero warnings and passes `genvm-lint validate`, which checks the contract's structure against the real GenLayer SDK.

## Running the tests

```bash
pip install -r requirements.txt
python -m pytest test/ -v
```

This runs 54 tests covering the cleaner, the trap, the judge response parsing, the attack corpus, and a consistency check that guards against the deployable bundle drifting from the tested source files.

## Deploying

GenVM deploys a single file's raw bytes as the contract code. It cannot see other files in this repository, so the contract as written in `contracts/evidence_guard.py`, which imports from `contracts/cleaner.py` and the other modules, cannot be deployed directly. A small script bundles everything into one self-contained file before deployment.

```bash
python deploy/build_bundle.py
genlayer deploy --contract contracts/evidence_guard_bundle.py
```

`test/test_bundle_consistency.py` checks that the generated bundle behaves identically to the tested source modules, so an edit to `cleaner.py`, `trap.py`, or `judge.py` that is not followed by rebuilding the bundle will fail a test rather than silently going out of sync.

## Attack corpus results

The corpus contains 13 evidence documents, each carrying one hidden instruction technique, and 6 ordinary documents that should pass through unchanged. Running every fixture through the cleaner alone, with no language model involved, gives the following results.

| Attack technique | Caught by the cleaner |
|-------------------|------------------------|
| Zero-width characters | Yes |
| HTML comment | Yes |
| White-on-white span | Yes |
| Hidden `display:none` div | Yes |
| Zero font size span | Yes |
| Image alt text | Yes |
| Fake `SYSTEM:` label | Yes |
| Fake `### Instruction` header | Yes |
| `[INST]` bracket markers | Yes |
| Reversed text via bidi override | Yes |
| Base64 encoded instruction | No |
| Instruction split across lines | No |
| Instruction in another language | No |

Ten of the thirteen attacks are caught by the cleaner alone, and five of the six clean documents pass through untouched. The three misses are expected rather than bugs. The cleaner only catches formatting based tricks. Semantically hidden instructions, such as a request written in another language or encoded in base64, are caught by the trap and the judge's own reading of the evidence in stages three and four, which require a live language model and are not exercised by this offline test.

Run `python -m pytest test/test_corpus.py -v` to reproduce these results.

## A known limitation

One clean document, a claim form whose own section header reads "Instructions: Complete all sections in black ink," has that header label stripped by the cleaner. At the regex level, an ordinary section header and an attacker's injected instruction label look the same: both are a label alone at the start of a line, followed by a colon. This is a low severity issue, since it removes a label rather than any evidence content and does not change the judge's verdict, but it is real. It is documented and pinned by a dedicated test rather than left as a silent surprise.

## A note for other builders

`gl.nondet.exec_prompt(prompt, response_format="json")` does not return JSON as text. GenVM parses the response itself and hands back an already decoded dictionary. Code written against the plain string pattern shown in GenLayer's own documentation examples, which manually strips markdown formatting and calls `json.loads`, will crash the moment it calls a string method on that dictionary.

Because every validator hits the same error on the same input, this does not look like an ordinary exception. It surfaces as a unanimous failure before consensus is reached, reported as `DETERMINISTIC_VIOLATION` on Bradbury and as `MAJORITY_DISAGREE` on Studio. That failure mode led to a long investigation into random number usage, storage type declarations, and closure serialization before the real, one line cause was found. `contracts/judge.py` now handles both a raw string response and a pre-parsed dictionary.

## Requirements

- A running GenLayer Studio, or the hosted version at [studio.genlayer.com](https://studio.genlayer.com)
- Python 3.11 or newer
- Node.js, used by the deploy script at `deploy/deployScript.ts`

## License

MIT. See [LICENSE](LICENSE).
