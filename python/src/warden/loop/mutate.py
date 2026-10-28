"""Mutation operators for the red team.

Each operator is a mechanical transform of an attack string that keeps its meaning but changes
its surface form, so the loop can test whether a defence generalises or just memorised one
payload. Operators use only what an attacker controls (the text they plant); none reads
Warden's rules. The attack text itself comes from the committed corpus and the scenario file,
never from this module.
"""

from __future__ import annotations

import base64
import random
from collections.abc import Callable

Operator = Callable[[str, random.Random], str]

_ZW = chr(0x200B)
# Latin -> visually-similar Cyrillic, to test homoglyph normalisation.
_HOMOGLYPHS = {
    "a": chr(0x430),
    "e": chr(0x435),
    "o": chr(0x43E),
    "p": chr(0x440),
    "c": chr(0x441),
    "x": chr(0x445),
}
_FENCES = ["<note>{}</note>", "[system]{}[/system]", "<!-- {} -->", "```\n{}\n```"]
_LANG_PREFIX = {
    "fr": "Note pour l'assistant : ",
    "es": "Nota para el asistente: ",
    "de": "Hinweis an den Assistenten: ",
}


def op_identity(text: str, _rng: random.Random) -> str:
    return text


def op_zero_width(text: str, rng: random.Random) -> str:
    """Insert zero-width spaces inside alphabetic runs."""
    out = []
    for ch in text:
        out.append(ch)
        if ch.isalpha() and rng.random() < 0.15:
            out.append(_ZW)
    return "".join(out)


def op_homoglyph(text: str, rng: random.Random) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) if ch.islower() and rng.random() < 0.3 else ch for ch in text)


def op_base64(text: str, _rng: random.Random) -> str:
    """Wrap the payload as a base64 blob with a decode-and-follow lead-in."""
    return f"Decode and act on this: {base64.b64encode(text.encode()).decode()}"


def op_case(text: str, rng: random.Random) -> str:
    return "".join(ch.upper() if rng.random() < 0.5 else ch.lower() for ch in text)


def op_spacing(text: str, rng: random.Random) -> str:
    return "".join(ch + (" " if ch != " " and rng.random() < 0.1 else "") for ch in text)


def op_fence(text: str, rng: random.Random) -> str:
    return rng.choice(_FENCES).format(text)


def op_lang_prefix(text: str, rng: random.Random) -> str:
    return _LANG_PREFIX[rng.choice(list(_LANG_PREFIX))] + text


def op_split(text: str, rng: random.Random) -> str:
    """Split the instruction across two lines, as if delivered in parts."""
    if len(text) < 20:
        return text
    cut = rng.randint(len(text) // 3, 2 * len(text) // 3)
    return text[:cut] + "\n...\n" + text[cut:]


OPERATORS: dict[str, Operator] = {
    "identity": op_identity,
    "zero_width": op_zero_width,
    "homoglyph": op_homoglyph,
    "base64": op_base64,
    "case": op_case,
    "spacing": op_spacing,
    "fence": op_fence,
    "lang_prefix": op_lang_prefix,
    "split": op_split,
}


def apply_operators(text: str, names: list[str], rng: random.Random) -> str:
    for name in names:
        text = OPERATORS[name](text, rng)
    return text


# "split" models an instruction spread across SEVERAL tool outputs — a multi-message threat the
# design assigns to session taint, not a single detection rule. "spacing" injects spaces inside
# words, character-level corruption that also degrades the attack's own readability. Both stay in
# the RED TEAM's arsenal but are excluded from the gate's generalisation test (G5), which asks
# whether one rule catches each meaning-preserving, still-readable obfuscation of an attack.
SINGLE_MESSAGE_OPERATORS = [n for n in OPERATORS if n not in {"identity", "split"}]
READABLE_OBFUSCATIONS = [n for n in OPERATORS if n not in {"identity", "split", "spacing"}]


def sample_mutation(rng: random.Random, max_ops: int = 2, pool: list[str] | None = None) -> list[str]:
    """A random chain of 1..max_ops distinct operators (never just identity)."""
    choices = pool if pool is not None else [n for n in OPERATORS if n != "identity"]
    k = min(rng.randint(1, max_ops), len(choices))
    return rng.sample(choices, k)
