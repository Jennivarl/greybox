"""
Stage 2 of Evidence Guard: strip hidden-instruction carriers from evidence
text before it ever reaches an LLM. Plain Python, no GenLayer imports,
no LLM calls, no consensus cost -- this runs deterministically the same
way on every node.

Every non-printable character this module cares about is built from an
integer codepoint (e.g. 0x200B) rather than pasted in literally, so the
source file stays provably plain ASCII and can't silently pick up a mangled
invisible character -- which would be an embarrassing bug in a tool whose
whole job is catching exactly that.
"""

import re
import unicodedata
from dataclasses import dataclass, field

# Invisible/formatting characters attackers hide instructions in, expressed
# as integer codepoints (not literal characters) so the source file stays
# provably plain ASCII: zero-width space/non-joiner/joiner, word joiner,
# zero-width no-break space (BOM), mongolian vowel separator, soft hyphen,
# arabic letter mark, bidi embedding/override controls, bidi isolate
# controls, and the supplementary-plane "tag" characters used in unicode-tag
# smuggling attacks.
_ZERO_WIDTH_CODEPOINTS = frozenset(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E]
)
_INVISIBLE_CONTROL_CODEPOINTS = frozenset(
    [0x00AD, 0x061C]
    + list(range(0x202A, 0x202F))  # LRE, RLE, PDF, LRO, RLO
    + list(range(0x2066, 0x206A))  # LRI, RLI, FSI, PDI
    + [0xE0001]
    + list(range(0xE0020, 0xE0080))  # unicode tag characters
)

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

# style="color:white" / "color:#fff" / "display:none" / "visibility:hidden" /
# font-size:0 spans, and matching <span ...>...</span> content.
_HIDDEN_STYLE_ATTR_RE = re.compile(
    r"""<(?P<tag>span|div|p|font)\b[^>]*style\s*=\s*["'][^"']*"""
    r"""(?:color\s*:\s*(?:white|#fff{3,6})|"""
    r"""display\s*:\s*none|"""
    r"""visibility\s*:\s*hidden|"""
    r"""font-size\s*:\s*0\w*|"""
    r"""opacity\s*:\s*0(?:\.0+)?)"""
    r"""[^"']*["'][^>]*>(?P<content>.*?)</(?P=tag)>""",
    re.IGNORECASE | re.DOTALL,
)

_IMG_ALT_RE = re.compile(
    r"""<img\b[^>]*\balt\s*=\s*["'](?P<alt>[^"']*)["'][^>]*>""",
    re.IGNORECASE,
)

# Fake role/instruction headers attackers prepend to smuggle a new system
# prompt: "SYSTEM: ...", "### Instruction\n...", "[INST]...", "Assistant:...".
# Matches only the label prefix at the start of a line -- the rest of the
# line is left as ordinary evidence text once the fake authority marker is
# gone.
_FAKE_ROLE_RE = re.compile(
    r"""^[ \t]*"""
    r"""(?:"""
    r"""\#{1,6}\s*(?:system|instructions?)\b[:\s]*"""
    r"""|\[/?(?:system|inst|instructions)\]\s*:?"""
    r"""|(?:system|assistant|instructions?)\s*:\s*"""
    r""")""",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class CleanResult:
    cleaned_text: str
    removed: list = field(default_factory=list)


def _strip_zero_width(text: str, removed: list) -> str:
    zero_width_count = sum(1 for ch in text if ord(ch) in _ZERO_WIDTH_CODEPOINTS)
    if zero_width_count:
        removed.append(f"zero_width_chars:{zero_width_count}")
    text = "".join(ch for ch in text if ord(ch) not in _ZERO_WIDTH_CODEPOINTS)

    control_count = sum(
        1 for ch in text if ord(ch) in _INVISIBLE_CONTROL_CODEPOINTS
    )
    if control_count:
        removed.append(f"invisible_control_chars:{control_count}")
    text = "".join(
        ch for ch in text if ord(ch) not in _INVISIBLE_CONTROL_CODEPOINTS
    )
    return text


def _strip_html_comments(text: str, removed: list) -> str:
    matches = _HTML_COMMENT_RE.findall(text)
    if matches:
        removed.append(f"html_comments:{len(matches)}")
    return _HTML_COMMENT_RE.sub("", text)


def _strip_hidden_styled_content(text: str, removed: list) -> str:
    def _record(match: "re.Match") -> str:
        removed.append(f"hidden_styled_content:{match.group('content')!r}")
        return ""

    return _HIDDEN_STYLE_ATTR_RE.sub(_record, text)


def _strip_image_alt_text(text: str, removed: list) -> str:
    def _record(match: "re.Match") -> str:
        alt = match.group("alt")
        if alt.strip():
            removed.append(f"image_alt_text:{alt!r}")
        return ""

    return _IMG_ALT_RE.sub(_record, text)


def _strip_fake_role_labels(text: str, removed: list) -> str:
    matches = _FAKE_ROLE_RE.findall(text)
    if matches:
        for m in matches:
            removed.append(f"fake_role_label:{m.strip()!r}")
    return _FAKE_ROLE_RE.sub("", text)


def _normalize_unicode(text: str, removed: list) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    if normalized != text:
        removed.append("unicode_normalized:NFKC")
    return normalized


def clean(text: str) -> CleanResult:
    """
    Strip known hidden-instruction carriers from `text`.

    Returns a CleanResult with the sanitized text and a list of what was
    removed. The removed list is itself evidence: a document that trips
    several of these strips is more suspicious than one that trips none,
    independent of whatever the LLM judge later decides.
    """
    if text is None:
        return CleanResult(cleaned_text="", removed=["input_was_none"])

    removed: list = []
    cleaned = text

    cleaned = _strip_html_comments(cleaned, removed)
    cleaned = _strip_hidden_styled_content(cleaned, removed)
    cleaned = _strip_image_alt_text(cleaned, removed)
    cleaned = _strip_zero_width(cleaned, removed)
    cleaned = _normalize_unicode(cleaned, removed)
    cleaned = _strip_fake_role_labels(cleaned, removed)

    # Collapse whitespace left behind by removed spans/comments so leftover
    # blank lines don't themselves become a distraction for the judge.
    cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = cleaned.strip()

    return CleanResult(cleaned_text=cleaned, removed=removed)
