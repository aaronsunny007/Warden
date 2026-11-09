"""Hidden-content scanner: text a model reads but a person never sees.

Prompt injections do not have to be visible. They hide in invisible Unicode, in white or
zero-size text inside a PDF, in CSS-hidden HTML, in comments and metadata, and in low-contrast
text inside an image. This module finds those, returns what was hidden, and builds a text
for the detection cascade that includes the hidden part. It does not decide a verdict by
itself; the cascade (and its rules) judge the recovered text.

Heuristics, not proofs. Notable limits, stated here so nobody has to guess:
  * PDF "white text" assumes a white page; we cannot see what is painted behind the text.
  * Invisible render mode (Tr 3) is also how scanned PDFs carry their OCR layer, so it is
    rated lower when the page has an image and no visible text.
  * Image OCR needs the optional `pytesseract` package and the `tesseract` binary. When
    either is missing the report says so (`notes`) instead of pretending the image is clean.
  * LSB steganography is only checked for plain printable-ASCII payloads.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import shutil
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

SEVERITIES = ("low", "medium", "high")
_ZW_BITS = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


@dataclass
class Finding:
    kind: str
    severity: str  # low | medium | high
    detail: str
    decoded: str = ""  # the hidden text this finding recovered, if any
    location: str = ""


@dataclass
class HiddenReport:
    findings: list[Finding] = field(default_factory=list)
    visible_text: str = ""
    hidden_text: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        top = max((SEVERITIES.index(f.severity) for f in self.findings), default=-1)
        return SEVERITIES[top] if top >= 0 else "none"

    @property
    def has_payload(self) -> bool:
        return bool(self.hidden_text.strip())

    def add(self, f: Finding) -> None:
        self.findings.append(f)
        if f.decoded:
            self.hidden_text = f"{self.hidden_text}\n{f.decoded}".strip()

    def detection_text(self) -> str:
        """What the cascade should read: the visible text plus everything that was hidden."""
        return f"{self.visible_text}\n{self.hidden_text}".strip()

    def merge(self, other: HiddenReport) -> None:
        self.findings.extend(other.findings)
        self.notes.extend(other.notes)
        self.hidden_text = f"{self.hidden_text}\n{other.hidden_text}".strip()


def _printable(s: str, floor: float = 0.9) -> bool:
    return bool(s) and sum(c.isprintable() or c in "\n\t" for c in s) / len(s) >= floor


def _runs(text: str, pred: Callable[[int], bool]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        if pred(ord(text[i])):
            j = i
            while j < len(text) and pred(ord(text[j])):
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    return out


def _decode_zero_width(run: str) -> str:
    """Zero-width characters used as binary: the two most common symbols are 0 and 1."""
    syms = sorted(set(run), key=run.count, reverse=True)
    if len(syms) < 2:
        return ""
    zero, one = syms[0], syms[1]
    bits = "".join("1" if c == one else "0" for c in run if c in (zero, one))
    chars = [chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits) - 7, 8)]
    s = "".join(chars)
    return s if _printable(s, 0.95) and len(s) >= 3 else ""


def _decode_variation(run: str) -> str:
    data = bytes((ord(c) - 0xFE00) if ord(c) <= 0xFE0F else (ord(c) - 0xE0100 + 16) for c in run)
    s = data.decode("utf-8", errors="ignore")
    return s if _printable(s, 0.95) and len(s) >= 3 else ""


def _script(c: str) -> str:
    if not c.isalpha():
        return ""
    name = unicodedata.name(c, "")
    for s in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(s):
            return s
    return "OTHER"


_CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "Α": "A",
    "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
}  # fmt: skip


def scan_text(text: str, location: str = "") -> HiddenReport:
    """Invisible Unicode, smuggled payloads, bidi overrides and mixed-script look-alike words."""
    r = HiddenReport(visible_text=_strip_invisible(text))

    tags = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        r.add(
            Finding("tag_smuggling", "high", f"{len(tags)} invisible Unicode tag characters", tags, location)
        )

    for a, b in _runs(text, lambda c: c in _ZW_BITS):
        run = text[a:b]
        if len(run) < 8:
            continue
        dec = _decode_zero_width(run)
        if dec:
            r.add(
                Finding(
                    "zero_width_payload",
                    "high",
                    f"{len(run)} zero-width characters encode text",
                    dec,
                    location,
                )
            )
        elif len(run) >= 16:
            r.add(
                Finding(
                    "zero_width_run", "medium", f"{len(run)} zero-width characters in a row", "", location
                )
            )

    for a, b in _runs(text, lambda c: 0xFE00 <= c <= 0xFE0F or 0xE0100 <= c <= 0xE01EF):
        run = text[a:b]
        if len(run) < 3:  # a single selector after an emoji is normal
            continue
        dec = _decode_variation(run)
        sev = "high" if dec else "medium"
        r.add(
            Finding(
                "variation_selector_payload", sev, f"{len(run)} variation selectors in a row", dec, location
            )
        )

    bidi = [c for c in text if ord(c) in _BIDI]
    if bidi:
        sev = "medium" if any(ord(c) == 0x202E for c in bidi) else "low"
        r.add(Finding("bidi_control", sev, f"{len(bidi)} bidirectional control characters", "", location))

    for m in re.finditer(r"\w{3,}", unicodedata.normalize("NFKC", text)):
        word = m.group(0)
        scripts = {_script(c) for c in word if c.isalpha()} - {""}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            folded = "".join(_CONFUSABLE.get(c, c) for c in word)
            r.add(
                Finding("mixed_script_word", "medium", f"look-alike letters inside {folded!r}", "", location)
            )
            break
    return r


def _strip_invisible(text: str) -> str:
    return "".join(
        c
        for c in text
        if not (
            ord(c) in _ZW_BITS
            or ord(c) in _BIDI
            or 0xFE00 <= ord(c) <= 0xFE0F
            or 0xE0000 <= ord(c) <= 0xE01EF
            or ord(c) in (0xAD, 0x180E)
        )
    )


# ---------------------------------------------------------------- HTML

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
_WHITE = {"white", "#fff", "#ffffff", "rgb(255,255,255)", "rgb(255, 255, 255)"}


def _css(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in style.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip().lower()] = v.strip().lower().replace("!important", "").strip()
    return out


def _px(v: str) -> float | None:
    m = re.match(r"^(-?\d+(?:\.\d+)?)(px|pt|em|rem|%|vw|vh)?$", v)
    return float(m.group(1)) if m else None


def _hidden_reason(tag: str, attrs: dict[str, str]) -> str:
    if tag in {"script", "style", "template", "noscript", "head", "title"}:
        return ""  # not rendered, but handled separately
    if "hidden" in attrs and attrs.get("type", "") != "hidden":
        return "the hidden attribute"
    c = _css(attrs.get("style", ""))
    if c.get("display") == "none":
        return "display:none"
    if c.get("visibility") in {"hidden", "collapse"}:
        return "visibility:hidden"
    if (px := _px(c.get("font-size", ""))) is not None and px <= 2:
        return f"font-size:{c['font-size']}"
    if c.get("opacity") and (px := _px(c["opacity"])) is not None and px < 0.05:
        return "opacity:0"
    if c.get("color", "") in _WHITE and c.get("background", c.get("background-color", "#fff")) in _WHITE | {
        ""
    }:
        return "white text on white"
    for side in ("left", "top", "text-indent"):
        if (px := _px(c.get(side, ""))) is not None and px <= -500:
            return f"{side}:{c[side]} (moved off-screen)"
    if c.get("overflow") == "hidden" and any(
        (_px(c.get(d, "")) == 0) for d in ("height", "width", "max-height")
    ):
        return "zero-size clipped box"
    return ""


class _HtmlWalker(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, str]] = []
        self.visible: list[str] = []
        self.hidden: list[tuple[str, str]] = []  # (reason, text)

    def _reason(self) -> str:
        for _, why in reversed(self.stack):
            if why:
                return why
        return ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        for key in ("alt", "title", "aria-label", "placeholder"):
            if a.get(key, "").strip():
                self.hidden.append((f"{key} attribute", a[key]))
        if tag == "input" and a.get("type") == "hidden" and a.get("value", "").strip():
            self.hidden.append(("hidden form field", a["value"]))
        if tag == "meta" and a.get("name", "").lower() in {"description", "keywords"} and a.get("content"):
            self.hidden.append((f"meta {a['name']}", a["content"]))
        if tag not in _VOID:
            why = ("an unrendered element" if tag in {"template", "noscript"} else "") or _hidden_reason(
                tag, a
            )
            self.stack.append((tag, why))

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data: str) -> None:
        if not data.strip():
            return
        top = self.stack[-1][0] if self.stack else ""
        if top in {"script", "style", "title"}:
            return
        why = self._reason()
        (self.hidden.append((why, data.strip())) if why else self.visible.append(data.strip()))

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.hidden.append(("an HTML comment", data.strip()))


def scan_html(html: str) -> HiddenReport:
    w = _HtmlWalker()
    w.feed(html)
    w.close()
    rep = scan_text(" ".join(w.visible))
    rep.visible_text = " ".join(w.visible)
    for why, text in w.hidden:
        sev = "low" if why.endswith("attribute") or why.startswith("meta") else "high"
        rep.add(Finding("html_hidden_text", sev, f"text hidden with {why}", text, "html"))
        rep.merge(scan_text(text, "html"))
    return rep


# ---------------------------------------------------------------- PDF


def _is_white(color: tuple[float, ...]) -> bool:
    return (
        bool(color) and min(color) >= 0.97
        if len(color) in (1, 3)
        else (len(color) == 4 and max(color) <= 0.03)
    )


def scan_pdf(data: bytes) -> HiddenReport:
    from pypdf import PdfReader  # optional dependency: pip install 'warden[files]'

    rep = HiddenReport()
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            reader.decrypt("")
        pages = list(reader.pages)
    except Exception as e:  # noqa: BLE001 - a malformed PDF is itself worth reporting
        rep.add(Finding("pdf_unreadable", "medium", f"could not parse the PDF: {type(e).__name__}"))
        return rep

    visible: list[str] = []
    for n, page in enumerate(pages, 1):
        state: dict[str, Any] = {"fill": (0.0,), "tr": 0}
        stack: list[tuple[tuple[float, ...], int]] = []
        mb = [float(x) for x in page.mediabox]
        chunks: list[tuple[str, str]] = []  # (reason, text)
        shown: list[str] = []

        def op(
            operator: Any, args: Any, cm: Any, tm: Any, state: dict[str, Any] = state, stack: Any = stack
        ) -> None:
            o = operator.decode("latin-1")
            nums = [float(a) for a in args if isinstance(a, (int, float))] if args else []
            if o == "q":
                stack.append((state["fill"], state["tr"]))
            elif o == "Q" and stack:
                state["fill"], state["tr"] = stack.pop()
            elif o in {"g", "rg", "k"} or (o in {"sc", "scn"} and len(nums) in (1, 3, 4)):
                state["fill"] = tuple(nums)
            elif o == "Tr" and nums:
                state["tr"] = int(nums[0])

        def text(
            t: str,
            cm: Any,
            tm: Any,
            font: Any,
            size: float,
            state: dict[str, Any] = state,
            chunks: Any = chunks,
            shown: Any = shown,
            mb: Any = mb,
        ) -> None:
            if not t.strip():
                return
            x = tm[4] * cm[0] + tm[5] * cm[2] + cm[4]
            y = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]
            eff = abs(size) * ((tm[2] ** 2 + tm[3] ** 2) ** 0.5) * ((cm[2] ** 2 + cm[3] ** 2) ** 0.5)
            why = ""
            if state["tr"] == 3:
                why = "invisible render mode"
            elif _is_white(state["fill"]):
                why = "near-white text (assumes a white page)"
            elif 0 < eff < 2:
                why = f"{eff:.1f}pt text"
            elif x < mb[0] - 5 or x > mb[2] + 5 or y < mb[1] - 5 or y > mb[3] + 5:
                why = "text positioned off the page"
            (chunks.append((why, t)) if why else shown.append(t))

        try:
            page.extract_text(visitor_operand_before=op, visitor_text=text)
        except Exception as e:  # noqa: BLE001
            rep.notes.append(f"page {n}: text extraction failed ({type(e).__name__})")
            continue
        has_image = bool(page.get("/Resources", {}).get("/XObject")) if hasattr(page, "get") else False
        page_visible = " ".join(shown).strip()
        visible.append(page_visible)
        for why, t in chunks:
            ocr_layer = why == "invisible render mode" and has_image and not page_visible
            sev = "low" if ocr_layer else ("medium" if why.startswith("near-white") else "high")
            kind = "pdf_ocr_layer" if ocr_layer else "pdf_hidden_text"
            rep.add(Finding(kind, sev, f"{why}", t.strip(), f"page {n}"))
        for annot in page.get("/Annots", []) or []:
            try:
                a = annot.get_object()
                content = str(a.get("/Contents", "")).strip()
                if content:
                    rep.add(Finding("pdf_annotation", "medium", "annotation text", content, f"page {n}"))
            except Exception:  # noqa: BLE001, S112
                continue

    rep.visible_text = "\n".join(v for v in visible if v)
    meta: dict[Any, Any] = dict(reader.metadata or {})
    for key, value in meta.items():
        v = str(value).strip()
        if v and len(v.split()) >= 4:
            rep.add(Finding("pdf_metadata", "low", f"long text in document property {key}", v, "metadata"))
    root = reader.trailer.get("/Root", {})
    if "/Names" in root and "/JavaScript" in (root["/Names"] or {}):
        rep.add(Finding("pdf_javascript", "medium", "document carries JavaScript"))
    for f in list(rep.findings):
        if f.decoded:
            rep.findings.extend(scan_text(f.decoded, f.location).findings)
    rep.merge(scan_text(rep.visible_text, "visible text"))
    rep.visible_text = rep.visible_text or ""
    return rep


# ---------------------------------------------------------------- images


def _lsb_text(img: Any) -> str:
    try:
        raw = img.convert("RGB").tobytes()[:60000]
    except Exception:  # noqa: BLE001
        return ""
    bits = "".join(str(ch & 1) for ch in raw)
    s = "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits) - 7, 8))
    m = re.search(r"[\x20-\x7e]{24,}", s)
    return m.group(0) if m and len(set(m.group(0))) > 6 else ""


def _ocr(img: Any) -> str:
    import pytesseract

    return str(pytesseract.image_to_string(img)).strip()


LOW_CONTRAST = 48  # a person reads text more easily than this, so text below it is effectively hidden


def _ocr_words(img: Any) -> Iterator[tuple[str, tuple[int, int, int, int]]]:
    import pytesseract

    d = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    for i, w in enumerate(d["text"]):
        w = w.strip()
        if len(w) >= 3 and w.isalpha() and float(d["conf"][i]) >= 60:
            yield w, (d["left"][i], d["top"][i], d["left"][i] + d["width"][i], d["top"][i] + d["height"][i])


def _box_contrast(gray: Any, box: tuple[int, int, int, int]) -> int:
    hist = gray.crop(box).histogram()
    total = sum(hist)
    if not total:
        return 255
    lo = hi = acc = 0
    for v, n in enumerate(hist):
        acc += n
        if acc >= total * 0.05 and not lo:
            lo = v
        if acc >= total * 0.95:
            hi = v
            break
    return hi - lo


def ocr_available() -> bool:
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        return False
    return shutil.which("tesseract") is not None


def scan_image(data: bytes) -> HiddenReport:
    from PIL import Image, ImageOps  # optional dependency: pip install 'warden[files]'

    rep = HiddenReport()
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as e:  # noqa: BLE001
        rep.add(Finding("image_unreadable", "medium", f"could not decode the image: {type(e).__name__}"))
        return rep

    for key, value in (img.info or {}).items():
        if isinstance(value, str) and len(value.split()) >= 4:
            rep.add(
                Finding(
                    "image_metadata",
                    "medium",
                    f"long text in image metadata field {key!r}",
                    value,
                    "metadata",
                )
            )
    try:
        exif = img.getexif()
        for tag in (
            0x010E,
            0x9286,
            0x013B,
            0x8298,
            0x9C9C,
        ):  # description, comment, artist, copyright, XP comment
            v = exif.get(tag)
            if isinstance(v, bytes):
                v = v.decode("utf-16-le", "ignore") if tag == 0x9C9C else v.decode("utf-8", "ignore")
            if isinstance(v, str) and len(v.split()) >= 4:
                rep.add(
                    Finding(
                        "image_metadata",
                        "medium",
                        f"long text in EXIF tag {hex(tag)}",
                        v.strip("\x00 "),
                        "exif",
                    )
                )
    except Exception:  # noqa: BLE001, S110
        pass

    lsb = _lsb_text(img)
    if lsb:
        rep.add(
            Finding("lsb_payload", "high", "printable text stored in the lowest colour bits", lsb, "pixels")
        )

    if not ocr_available():
        rep.notes.append(
            "OCR unavailable (install the 'files' extra and the tesseract binary): text drawn in the image was not read"
        )
        return rep
    gray = ImageOps.grayscale(img.convert("RGB"))
    rep.visible_text = _ocr(gray)
    low: dict[tuple[int, int], str] = {}
    strong: dict[tuple[int, int], str] = {}
    for variant in (
        gray,
        ImageOps.autocontrast(gray, cutoff=1),
        ImageOps.equalize(gray),
        ImageOps.invert(ImageOps.equalize(gray)),
    ):
        for word, box in _ocr_words(variant):
            key = (box[0] // 8, box[1] // 8)
            if _box_contrast(gray, box) < LOW_CONTRAST:
                low.setdefault(key, word)
            else:
                strong.setdefault(key, word)
    low = {k: w for k, w in low.items() if k not in strong}
    if len(low) >= 3:
        text = " ".join(w for _, w in sorted(low.items(), key=lambda kv: (kv[0][1], kv[0][0])))
        rep.add(
            Finding(
                "image_low_contrast_text",
                "high",
                f"{len(low)} words drawn at under {LOW_CONTRAST}/255 contrast",
                text,
                "pixels",
            )
        )
        rep.visible_text = " ".join(w for _, w in sorted(strong.items(), key=lambda kv: (kv[0][1], kv[0][0])))
    rep.merge(scan_text(rep.visible_text, "ocr"))
    return rep


# ---------------------------------------------------------------- entry point


def sniff(data: bytes) -> str:
    if data[:5] == b"%PDF-":
        return "pdf"
    if (
        data[:8] == b"\x89PNG\r\n\x1a\n"
        or data[:3] == b"\xff\xd8\xff"
        or data[:6] in (b"GIF87a", b"GIF89a")
        or data[:4] == b"RIFF"
    ):
        return "image"
    return "html" if re.search(rb"<\s*(html|body|div|p|span|a)\b", data[:4096], re.I) else "text"


def scan(data: bytes | str, kind: str = "auto") -> HiddenReport:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    k = sniff(raw) if kind == "auto" else kind
    if k == "pdf":
        return scan_pdf(raw)
    if k == "image":
        return scan_image(raw)
    s = raw.decode("utf-8", errors="replace")
    return scan_html(s) if k == "html" else scan_text(s)


def decode_b64(content: str) -> bytes:
    try:
        return base64.b64decode(content, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("content_base64 is not valid base64") from e
