"""
ClearText — core/validation.py

Every byte that reaches a processing pipeline passes through here first.
This module is the security perimeter: magic-byte verification, size/pixel
ceilings, and PDF-specific exploit screening (embedded JS, launch actions,
external reference injection, pathological object graphs).

Design note: we deliberately validate structure with PyMuPDF/pikepdf *before*
ever handing bytes to a raster decoder (Pillow/OpenCV), and we never trust the
client-supplied Content-Type header — detection is by magic bytes only.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass
from enum import Enum

import fitz  # PyMuPDF
import pikepdf
from PIL import Image

from .config import settings

Image.MAX_IMAGE_PIXELS = settings.MAX_IMAGE_PIXELS  # decompression-bomb guard


class DocKind(str, Enum):
    PDF = "pdf"
    RASTER_IMAGE = "raster_image"


class ValidationError(Exception):
    """Raised for any input that fails sanitization. Message is user-safe."""


@dataclass(frozen=True)
class ValidationResult:
    kind: DocKind
    page_count: int
    sanitized_bytes: bytes  # rebuilt/sanitized document, safe to process


_MAGIC_SIGNATURES = {
    b"%PDF-": DocKind.PDF,
    b"\x89PNG\r\n\x1a\n": DocKind.RASTER_IMAGE,
    b"\xff\xd8\xff": DocKind.RASTER_IMAGE,          # JPEG
    b"II*\x00": DocKind.RASTER_IMAGE,               # TIFF little-endian
    b"MM\x00*": DocKind.RASTER_IMAGE,               # TIFF big-endian
}

# PDF actions/keys that have no legitimate use in this "flatten a document"
# workload under any circumstances — presence anywhere in the raw bytes is
# treated as hostile intent, not something we try to strip-and-continue.
# NOTE: /AA is deliberately NOT in this coarse list. Unlike the tokens
# below, /AA (Additional Actions) dictionaries are extremely common in
# ordinary PDFs — Acrobat/Word exports, e-signature platforms, and fillable
# forms all use them for benign triggers (e.g. "jump to page 3 on open").
# Blanket-rejecting on /AA's mere presence produced a high false-positive
# rate against real-world documents. /AA is instead evaluated structurally
# in _find_dangerous_additional_actions() below, which only rejects when an
# /AA-triggered action chain actually resolves to a dangerous subtype.
_DANGEROUS_PDF_TOKENS = [
    rb"/JavaScript",
    rb"/JS\b",
    rb"/Launch",
    rb"/OpenAction",
    rb"/EmbeddedFile",
    rb"/RichMedia",
    rb"/SubmitForm",
    rb"/ImportData",
    rb"/GoToR",  # remote go-to — external reference injection vector
    rb"/GoToE",
]

# Action subtypes (the PDF action dictionary's /S value) that are always
# treated as dangerous, wherever they're triggered from. Kept in sync with
# the coarse token list above — these are the same threats, just evaluated
# structurally instead of by raw-byte pattern match when they arrive via /AA.
_DANGEROUS_ACTION_SUBTYPES = {
    "JavaScript", "Launch", "SubmitForm", "ImportData", "GoToR", "GoToE",
}


def sniff_kind(raw: bytes) -> DocKind:
    for sig, kind in _MAGIC_SIGNATURES.items():
        if raw.startswith(sig):
            return kind
    raise ValidationError("Unrecognized or unsupported file type.")


def _enforce_size(raw: bytes) -> None:
    if len(raw) == 0:
        raise ValidationError("Empty file.")
    if len(raw) > settings.MAX_UPLOAD_BYTES:
        raise ValidationError(
            f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_BYTES} bytes."
        )


def _scan_for_dangerous_tokens(raw: bytes) -> list[str]:
    hits = []
    for pattern in _DANGEROUS_PDF_TOKENS:
        if re.search(pattern, raw):
            hits.append(pattern.decode(errors="replace"))
    return hits


def _check_object_graph_limits(pdf: pikepdf.Pdf) -> None:
    obj_count = len(pdf.objects)
    if obj_count > settings.MAX_PDF_OBJECTS:
        raise ValidationError("Document object graph exceeds safe processing limits.")

    if len(pdf.pages) > settings.MAX_PDF_PAGES:
        raise ValidationError("Document exceeds maximum supported page count.")

    # Guard against deeply nested /Pages trees or recursive resource
    # dictionaries designed to blow the stack of a naive parser.
    def _depth(obj, seen: set, depth: int = 0) -> int:
        if depth > settings.MAX_PDF_NEST_DEPTH:
            raise ValidationError("Document structure exceeds maximum nesting depth.")
        oid = id(obj)
        if oid in seen:
            return depth  # cycle — pikepdf's own loader already tolerates this
        seen.add(oid)
        max_child_depth = depth
        try:
            if isinstance(obj, (pikepdf.Dictionary, pikepdf.Array)):
                items = obj.values() if isinstance(obj, pikepdf.Dictionary) else obj
                for child in items:
                    if isinstance(child, (pikepdf.Dictionary, pikepdf.Array)):
                        max_child_depth = max(max_child_depth, _depth(child, seen, depth + 1))
        except Exception:
            pass
        return max_child_depth

    _depth(pdf.Root, set())


def _collect_action_subtypes(action: object, found: set[str], depth: int = 0) -> None:
    """
    Walks a single PDF action dictionary and follows its /Next chain (an
    action can trigger a further action or array of actions on completion),
    collecting every action subtype (/S) encountered.
    """
    if depth > 25 or not isinstance(action, pikepdf.Dictionary):
        return  # depth guard against a maliciously/accidentally cyclic chain

    subtype = action.get("/S")
    if subtype is not None:
        name = str(subtype).lstrip("/")
        found.add(name)

    nxt = action.get("/Next")
    if nxt is None:
        return
    if isinstance(nxt, pikepdf.Array):
        for item in nxt:
            _collect_action_subtypes(item, found, depth + 1)
    else:
        _collect_action_subtypes(nxt, found, depth + 1)


def _collect_aa_subtypes(aa_dict: object, found: set[str]) -> None:
    """An /AA dictionary maps trigger names (/O, /C, /E, /X, /WC, ...) to
    individual action dictionaries — check every trigger, not just one."""
    if not isinstance(aa_dict, pikepdf.Dictionary):
        return
    for _trigger, action in aa_dict.items():
        _collect_action_subtypes(action, found)


def _find_dangerous_additional_actions(pdf: pikepdf.Pdf) -> set[str]:
    """
    Structurally evaluates every /AA dictionary in the document — at the
    document root, on each page, on each page's annotations, and on AcroForm
    fields (including nested /Kids) — and returns the set of dangerous
    action subtypes actually referenced, if any. An empty result means /AA
    dictionaries may be present but only trigger benign actions (GoTo,
    Named, Hide, etc.), which is the common case for real-world documents.
    """
    all_subtypes: set[str] = set()

    root = pdf.Root
    if "/AA" in root:
        _collect_aa_subtypes(root["/AA"], all_subtypes)

    for page in pdf.pages:
        if "/AA" in page:
            _collect_aa_subtypes(page["/AA"], all_subtypes)

        annots = page.get("/Annots")
        if annots is not None:
            for annot in annots:
                if isinstance(annot, pikepdf.Dictionary) and "/AA" in annot:
                    _collect_aa_subtypes(annot["/AA"], all_subtypes)

    def _walk_fields(fields: object, depth: int = 0) -> None:
        if depth > 25 or fields is None:
            return
        for field in fields:
            if not isinstance(field, pikepdf.Dictionary):
                continue
            if "/AA" in field:
                _collect_aa_subtypes(field["/AA"], all_subtypes)
            _walk_fields(field.get("/Kids"), depth + 1)

    acroform = root.get("/AcroForm")
    if isinstance(acroform, pikepdf.Dictionary):
        _walk_fields(acroform.get("/Fields"))

    return all_subtypes & _DANGEROUS_ACTION_SUBTYPES


def _sanitize_pdf(raw: bytes) -> ValidationResult:
    # Fast, coarse rejection for tokens that have no legitimate use in this
    # workflow under any circumstances, checked before we bother opening the
    # file structurally.
    hits = _scan_for_dangerous_tokens(raw)
    if hits:
        raise ValidationError(
            "Document rejected: contains disallowed active content "
            f"({', '.join(sorted(set(hits)))})."
        )

    try:
        pdf = pikepdf.open(io.BytesIO(raw))
    except pikepdf.PasswordError:
        raise ValidationError("Encrypted/password-protected PDFs are not supported.")
    except Exception as exc:
        raise ValidationError(f"Malformed or corrupt PDF: {exc}")

    with pdf:
        _check_object_graph_limits(pdf)

        dangerous_actions = _find_dangerous_additional_actions(pdf)
        if dangerous_actions:
            raise ValidationError(
                "Document rejected: an additional-actions (/AA) trigger references "
                f"disallowed action type(s) ({', '.join(sorted(dangerous_actions))})."
            )

        # Belt-and-suspenders: strip whatever action dictionaries remain —
        # including benign ones that passed the check above — before further
        # processing. This pipeline has no need to preserve interactive
        # open/close/navigation behavior in its output regardless of whether
        # it was dangerous, so there's no downside to dropping it entirely.
        root = pdf.Root
        if "/OpenAction" in root:
            del root["/OpenAction"]
        if "/AA" in root:
            del root["/AA"]
        for page in pdf.pages:
            if "/AA" in page:
                del page["/AA"]

        # Rebuild losslessly through pikepdf — this normalizes the xref table,
        # drops orphaned/unreachable objects, and neutralizes many structural
        # exploits (bad xref chains, duplicate object numbers) by construction.
        out = io.BytesIO()
        pdf.save(out, linearize=False)
        sanitized = out.getvalue()

    # Confirm the sanitized doc opens cleanly and get a trustworthy page count.
    doc = fitz.open(stream=sanitized, filetype="pdf")
    try:
        page_count = doc.page_count
        if page_count == 0:
            raise ValidationError("PDF contains no pages.")
    finally:
        doc.close()

    return ValidationResult(kind=DocKind.PDF, page_count=page_count, sanitized_bytes=sanitized)


def _sanitize_raster(raw: bytes) -> ValidationResult:
    try:
        img = Image.open(io.BytesIO(raw))
        img.verify()  # structural check only; re-open below to actually decode
    except Exception as exc:
        raise ValidationError(f"Malformed or corrupt image: {exc}")

    try:
        img = Image.open(io.BytesIO(raw))
        img.load()  # forces full decode now, inside our size guard
    except Exception as exc:
        raise ValidationError(f"Unable to decode image data: {exc}")

    w, h = img.size
    if max(w, h) > settings.MAX_IMAGE_DIMENSION:
        raise ValidationError(
            f"Image dimensions exceed the {settings.MAX_IMAGE_DIMENSION}px per-side limit."
        )
    if w * h > settings.MAX_IMAGE_PIXELS:
        raise ValidationError("Image pixel count exceeds safe processing limits.")

    # Re-encode losslessly through Pillow to strip any polyglot payload or
    # malformed ancillary chunks (EXIF-borne exploits, tEXt/iCCP bombs, etc.)
    # riding alongside the pixel data.
    out = io.BytesIO()
    fmt = "PNG" if img.mode in ("RGBA", "P", "LA") else "TIFF"
    img.save(out, format=fmt)
    return ValidationResult(kind=DocKind.RASTER_IMAGE, page_count=1, sanitized_bytes=out.getvalue())


def screen_pdf_for_forensics(raw: bytes) -> None:
    """
    A DELIBERATELY LIGHTER check than validate_and_sanitize(): raises
    ValidationError on the same exploit signals and structural-limit
    violations, but never rebuilds the PDF via pikepdf.save().

    This distinction matters specifically for revision forensics
    (revision_forensics.py): validate_and_sanitize()'s rebuild step
    normalizes the file and collapses its /Prev incremental-save chain into
    a single consolidated revision — exactly the history that forensic
    discovery needs to find. Discovery must run against the untouched raw
    upload, so it uses this function instead: same malicious-content
    screening, same object-graph limits, but the bytes it inspects (and
    that the caller goes on to use) are never rewritten.
    """
    _enforce_size(raw)
    kind = sniff_kind(raw)
    if kind is not DocKind.PDF:
        raise ValidationError("Only PDF documents are supported for this operation.")

    hits = _scan_for_dangerous_tokens(raw)
    if hits:
        raise ValidationError(
            "Document rejected: contains disallowed active content "
            f"({', '.join(sorted(set(hits)))})."
        )

    try:
        pdf = pikepdf.open(io.BytesIO(raw))
    except pikepdf.PasswordError:
        raise ValidationError("Encrypted/password-protected PDFs are not supported.")
    except Exception as exc:
        raise ValidationError(f"Malformed or corrupt PDF: {exc}")

    with pdf:
        _check_object_graph_limits(pdf)
        dangerous_actions = _find_dangerous_additional_actions(pdf)
        if dangerous_actions:
            raise ValidationError(
                "Document rejected: an additional-actions (/AA) trigger references "
                f"disallowed action type(s) ({', '.join(sorted(dangerous_actions))})."
            )
    # No save() call — raw bytes are returned to the caller unmodified by
    # design; this function only raises or returns None.


def validate_and_sanitize(raw: bytes) -> ValidationResult:
    """
    Single entry point. Raises ValidationError with a user-safe message on
    any rejection; returns re-encoded/rebuilt bytes that are safe to hand to
    the vector or raster pipeline on success.
    """
    _enforce_size(raw)
    kind = sniff_kind(raw)
    if kind is DocKind.PDF:
        return _sanitize_pdf(raw)
    return _sanitize_raster(raw)
