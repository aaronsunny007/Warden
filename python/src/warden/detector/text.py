"""Text normalisation shared by the embedder and classifier (mirrors the gateway's)."""

from __future__ import annotations

import re
import unicodedata

_INVISIBLE = re.compile(
    "["
    + "".join(chr(c) for c in (0x00AD, 0x180E, 0xFEFF))
    + chr(0x200B)
    + "-"
    + chr(0x200F)
    + chr(0x202A)
    + "-"
    + chr(0x202E)
    + chr(0x2060)
    + "-"
    + chr(0x2064)
    + chr(0x2066)
    + "-"
    + chr(0x206F)
    + chr(0xFE00)
    + "-"
    + chr(0xFE0F)
    + "]"
)
_TAGS = re.compile("[" + chr(0xE0000) + "-" + chr(0xE007F) + "]")
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    smuggled = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    t = unicodedata.normalize("NFKC", text)
    t = _TAGS.sub("", _INVISIBLE.sub("", t))
    if smuggled:
        t = f"{t} {smuggled}"
    return _WS.sub(" ", t).strip()
