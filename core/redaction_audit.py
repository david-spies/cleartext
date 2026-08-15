"""
ClearText — core/redaction_audit.py

READ-ONLY / AUDIT-ONLY MODULE. This is deliberately a separate feature from
the border/artifact cleanup pipelines (vector_pipeline.py, raster_pipeline.py)
and must never be wired into a path that modifies or returns a cleaned
document. Its entire purpose is to answer one question: "did a redaction in
this PDF actually remove the underlying content, or just draw a box on top
of it?" — and to report that finding without becoming a tool for unmasking
other people's redactions.

WHAT THIS DETECTS
  A redaction box is only a REAL redaction if the underlying content was
  actually deleted from the content stream. Many "redactions" are just an
  opaque rectangle (a vector fill, or a solid-color image) painted on top of
  live, still-selectable, still-extractable text. This module finds:

    1. Opaque solid-fill vector rectangles with extractable text underneath.
    2. Opaque solid-color raster images placed on top of extractable text.
    3. PDF /Redact annotations that were added but never *applied* — the PDF
       spec's redaction annotation is explicitly a two-step process (mark,
       then burn-in via apply-redaction); a mark with no burn-in leaves the
       original content fully intact underneath a purely cosmetic overlay.

WHAT THIS DOES NOT DO
  - Never modifies the input document in any way.
  - Never returns the hidden text by default. `reveal_text=True` is an
    explicit opt-in for a document owner doing their own remediation — see
    the warning on `audit_pdf()`. The default output reports character/word
    COUNTS and locations only, which is enough to prove a redaction failed
    without itself leaking the sensitive content.
  - Does not attempt anything on flattened raster images (PNG/JPEG/TIFF) —
    those have no text layer to check against, by definition. This module
    is PDF-only; a scanned image with a hand-drawn black box has no
    extractable text either way and this technique cannot evaluate it.

Detection criteria are intentionally NOT the same as vector_pipeline.py's
border-artifact heuristics: a redaction box can appear anywhere on a page
(not just the edge band) and is usually much smaller than a full-margin
scanner artifact, so there's no edge-band gate or large min-span-ratio here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

import fitz  # PyMuPDF

from .config import settings


class RedactionSource(str, Enum):
    VECTOR_FILL = "vector_fill"
    IMAGE_OVERLAY = "image_overlay"
    UNAPPLIED_REDACT_ANNOTATION = "unapplied_redact_annotation"


class RiskLevel(str, Enum):
    CRITICAL = "critical"   # extractable text found underneath an opaque box
    CLEAR = "clear"         # box present, no extractable text underneath
    UNKNOWN = "unknown"     # couldn't conclusively evaluate (see `note`)


@dataclass(frozen=True)
class RedactionFinding:
    page_number: int
    rect: tuple[float, float, float, float]
    source: RedactionSource
    risk_level: RiskLevel
    underlying_word_count: int
    underlying_char_count: int
    note: str
    revealed_text: str | None = None  # only populated when reveal_text=True


@dataclass
class RedactionAuditReport:
    total_boxes_found: int
    critical_count: int
    clear_count: int
    unknown_count: int
    findings: list[RedactionFinding] = field(default_factory=list)
    pages_audited: int = 0
    summary: str = ""


def _is_dark(rgb: tuple[float, float, float] | None) -> bool:
    if rgb is None:
        return False
    r, g, b = rgb
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return luminance <= settings.AUDIT_DARKNESS_THRESHOLD


def _qualifies_as_candidate(rect: fitz.Rect, page_rect: fitz.Rect) -> bool:
    page_area = page_rect.width * page_rect.height
    if page_area <= 0:
        return False
    area_ratio = (rect.width * rect.height) / page_area
    return settings.AUDIT_MIN_BOX_AREA_RATIO <= area_ratio <= settings.AUDIT_MAX_BOX_AREA_RATIO


def _find_vector_candidates(page: fitz.Page) -> list[fitz.Rect]:
    candidates = []
    page_rect = page.rect
    for drawing in page.get_drawings():
        if not drawing.get("fill"):
            continue
        rect = drawing.get("rect")
        if rect is None:
            continue
        rect = fitz.Rect(rect)

        opacity = drawing.get("fill_opacity", 1.0) or 1.0
        if opacity < settings.AUDIT_MIN_OPACITY:
            continue

        fill_color = drawing.get("fill")
        if not settings.AUDIT_ANY_SOLID_COLOR and not _is_dark(fill_color):
            continue

        if not _qualifies_as_candidate(rect, page_rect):
            continue

        candidates.append(rect)
    return candidates


def _find_image_overlay_candidates(page: fitz.Page) -> list[fitz.Rect]:
    """
    An embedded raster image placed on top of text, where the image itself
    is essentially a single flat color, is functionally identical to a
    vector-fill redaction box — just authored differently.
    """
    candidates = []
    page_rect = page.rect
    doc = page.parent

    for img in page.get_images(full=True):
        xref = img[0]
        try:
            rects = page.get_image_rects(xref)
        except Exception:
            continue
        for rect in rects:
            rect = fitz.Rect(rect)
            if not _qualifies_as_candidate(rect, page_rect):
                continue
            try:
                pixmap = fitz.Pixmap(doc, xref)
                if pixmap.n > 4:  # CMYK or unusual colorspace — convert for a fair check
                    pixmap = fitz.Pixmap(fitz.csRGB, pixmap)
                samples = pixmap.samples
                if not samples:
                    continue
                import numpy as np  # local import: only needed on this path
                arr = np.frombuffer(samples, dtype=np.uint8)
                channels = pixmap.n
                arr = arr.reshape(-1, channels)[:, :3] if channels >= 3 else arr.reshape(-1, 1)
                variance = float(np.var(arr.astype(np.float32)))
                mean_intensity = float(arr.mean())
                if variance <= settings.AUDIT_IMAGE_COLOR_VARIANCE_MAX and (
                    settings.AUDIT_ANY_SOLID_COLOR or mean_intensity <= 255 * (1 - settings.AUDIT_DARKNESS_THRESHOLD)
                ):
                    candidates.append(rect)
            except Exception:
                continue  # unreadable/unsupported image stream — skip, don't crash the audit
    return candidates


def _find_unapplied_redact_annotations(page: fitz.Page) -> list[fitz.Rect]:
    """
    A PDF /Redact annotation that was placed but never burned in via
    apply_redactions() is the clearest possible signal of a failed
    redaction: the tool that made it intended to remove content, and never
    finished the job.
    """
    rects = []
    try:
        for annot in page.annots() or []:
            if annot.type[1] == "Redact":
                rects.append(fitz.Rect(annot.rect))
    except Exception:
        pass
    return rects


def _check_text_under_rect(page: fitz.Page, rect: fitz.Rect) -> tuple[int, int, str]:
    """Returns (word_count, char_count, joined_text) of extractable text overlapping rect."""
    words = page.get_text("words", clip=rect)  # (x0,y0,x1,y1, word, block, line, word_no)
    if not words:
        return 0, 0, ""
    text = " ".join(w[4] for w in words)
    return len(words), len(text), text


def _dedupe_rects(rects: list[fitz.Rect], tolerance: float = 2.0) -> list[fitz.Rect]:
    """Multiple detection paths (vector + image + annotation) can find the
    same physical box. Collapse near-identical rects to one finding."""
    unique: list[fitz.Rect] = []
    for r in rects:
        if not any(
            abs(r.x0 - u.x0) < tolerance and abs(r.y0 - u.y0) < tolerance
            and abs(r.x1 - u.x1) < tolerance and abs(r.y1 - u.y1) < tolerance
            for u in unique
        ):
            unique.append(r)
    return unique


def audit_page(page: fitz.Page, reveal_text: bool = False) -> list[RedactionFinding]:
    findings: list[RedactionFinding] = []

    vector_candidates = _find_vector_candidates(page)
    image_candidates = _find_image_overlay_candidates(page)
    annot_rects = _find_unapplied_redact_annotations(page)

    # Unapplied annotations are unambiguous — report them directly, they
    # don't need a text-overlap check to be worth flagging.
    for rect in _dedupe_rects(annot_rects):
        word_count, char_count, text = _check_text_under_rect(page, rect)
        findings.append(RedactionFinding(
            page_number=page.number,
            rect=(rect.x0, rect.y0, rect.x1, rect.y1),
            source=RedactionSource.UNAPPLIED_REDACT_ANNOTATION,
            risk_level=RiskLevel.CRITICAL,
            underlying_word_count=word_count,
            underlying_char_count=char_count,
            note=(
                "A redaction annotation was placed but never applied — the marked "
                "content was never actually removed from the page."
            ),
            revealed_text=text if (reveal_text and char_count > 0) else None,
        ))

    for rect, source in [(r, RedactionSource.VECTOR_FILL) for r in _dedupe_rects(vector_candidates)] + \
                         [(r, RedactionSource.IMAGE_OVERLAY) for r in _dedupe_rects(image_candidates)]:
        word_count, char_count, text = _check_text_under_rect(page, rect)
        if char_count > 0:
            findings.append(RedactionFinding(
                page_number=page.number,
                rect=(rect.x0, rect.y0, rect.x1, rect.y1),
                source=source,
                risk_level=RiskLevel.CRITICAL,
                underlying_word_count=word_count,
                underlying_char_count=char_count,
                note=(
                    "Opaque box detected with extractable text underneath — this "
                    "redaction likely only covers the content visually and can be "
                    "recovered by selecting/copying or programmatic text extraction."
                ),
                revealed_text=text if reveal_text else None,
            ))
        else:
            findings.append(RedactionFinding(
                page_number=page.number,
                rect=(rect.x0, rect.y0, rect.x1, rect.y1),
                source=source,
                risk_level=RiskLevel.CLEAR,
                underlying_word_count=0,
                underlying_char_count=0,
                note=(
                    "Opaque box detected with no extractable text underneath. This is "
                    "consistent with a properly burned-in redaction, but cannot rule out "
                    "a flattened/rasterized page where no text layer exists at all — "
                    "verify the box's origin if this document started as a scan."
                ),
            ))

    return findings


def audit_pdf(
    sanitized_pdf_bytes: bytes,
    reveal_text: bool = False,
) -> RedactionAuditReport:
    """
    Read-only entry point. Never modifies sanitized_pdf_bytes and never
    returns a document — only a structured report.

    reveal_text: WARNING — set this to True only when the caller is the
    document's own owner performing remediation on their own file. When
    True, CRITICAL findings include the actual extracted text hidden under
    a failed redaction box. This is the one place in ClearText where
    sensitive content can be surfaced, so callers (API layers, CLI tools)
    built on this function should gate it behind an explicit, deliberate
    user action — never default it on, and never expose it in a bulk/batch
    or unauthenticated flow.
    """
    doc = fitz.open(stream=sanitized_pdf_bytes, filetype="pdf")
    all_findings: list[RedactionFinding] = []

    try:
        for page in doc:
            all_findings.extend(audit_page(page, reveal_text=reveal_text))
        pages_audited = doc.page_count
    finally:
        doc.close()

    critical = sum(1 for f in all_findings if f.risk_level == RiskLevel.CRITICAL)
    clear = sum(1 for f in all_findings if f.risk_level == RiskLevel.CLEAR)
    unknown = sum(1 for f in all_findings if f.risk_level == RiskLevel.UNKNOWN)

    if critical:
        summary = (
            f"{critical} potential redaction failure(s) found: opaque box(es) with "
            f"extractable text still present underneath. Treat this document as "
            f"NOT safely redacted until remediated."
        )
    elif all_findings:
        summary = (
            f"{len(all_findings)} opaque box(es) reviewed; none had extractable text "
            f"underneath. No redaction failures detected by this method — see per-finding "
            f"notes for coverage limitations."
        )
    else:
        summary = "No candidate redaction boxes were found on this document."

    return RedactionAuditReport(
        total_boxes_found=len(all_findings),
        critical_count=critical,
        clear_count=clear,
        unknown_count=unknown,
        findings=all_findings,
        pages_audited=pages_audited,
        summary=summary,
    )
