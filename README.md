# Evidence Guard

Any GenLayer contract that reads text or images written by the parties it judges can be manipulated by them. This stops that.

Evidence Guard is a Python Intelligent Contract on GenLayer that screens evidence for hidden instructions (prompt injection) before an AI judge contract ever reads it. Other contracts import it, hand it raw evidence, and get back a verdict they can trust -- and optionally a permanent, provable record of that verdict.

Full build plan: see `GREYBOX.md` in [genlayer-school](https://github.com/Jennivarl/genlayer-school) (this repo's design doc, kept alongside the rest of the author's GenLayer work).

## Status

- [x] Stage 2 -- the cleaner (plain Python, no LLM, no consensus cost): [`contracts/cleaner.py`](contracts/cleaner.py), tested in [`test/test_cleaner.py`](test/test_cleaner.py)
- [ ] Stage 3 -- the trap (per-tx seeded canary word)
- [ ] Stage 4 -- the judge call (structured LLM verdict + custom validator)
- [ ] Stage 5 -- the contract wrapper (`EvidenceGuard`, `TreeMap` storage)
- [ ] Stage 6 -- the attack corpus (~15 test files, pass-rate table)
- [ ] Stage 7 -- deploy to testnet Bradbury

## The cleaner

`clean(text)` strips known hidden-instruction carriers before evidence reaches the LLM, and returns what it removed alongside the cleaned text -- the removal list is evidence in itself:

- Invisible characters (zero-width space/joiner/non-joiner, word joiner, BOM, bidi overrides, unicode tag characters)
- HTML comments
- White-on-white / `display:none` / `visibility:hidden` / `font-size:0` spans
- Image alt text
- Fake role labels (`SYSTEM:`, `### Instruction`, `[INST]...[/INST]`)

```bash
pip install -r requirements.txt
python -m pytest test/test_cleaner.py -v
```

## Requirements

- A running GenLayer Studio, or the hosted version at [studio.genlayer.com](https://studio.genlayer.com)
- Python 3.11+ for the contract and tests
- Node.js for the deploy script (`deploy/deployScript.ts`)

## License

MIT -- see [LICENSE](LICENSE).
