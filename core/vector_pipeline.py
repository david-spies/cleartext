"""
ClearText — core/vector_pipeline.py

Handles digitally-authored PDFs: parses each page's drawing operations via
PyMuPDF's `get_drawings()` (a structured view over the content stream's path
painting operators) and flags filled shapes that look like injected black
border/margin overlays rather than legitimate page styling.

Two remediation modes:
  - "mask"   (default, non-destructive): draws a background-colored rectangle
             on top of the offending shape as a *new* content stream
             operation. The original path operators — and every text string —
             are left completely untouched, so nothing downstream can ever
             be "corrupted." This is the safe default for production.
  - "redact" (aggressive): uses PyMuPDF redaction annotations to truly erase
             content in the flagged region, including any text that overlaps
             it. Only appropriate when the caller has confirmed the region is
             pure margin with no legitimate content underneath.

A shape only qualifies as an "artifact candidate" if it passes ALL of:
  1. It's a filled (not merely stroked) path.
  2. Its fill is dark/near-black (avoids nuking legitimate colored graphics).
  3. It sits within the page's outer edge band (a true border, not a table
     cell or a chart bar in the middle of the page).
  4. It spans a large fraction of the page's width or height (a stray small
     black square is very likely intentional content, not a scan artifact).
  5. It's effectively opaque.

This conjunction is intentionally conservative — false negatives (missing a
border) are far preferable to false positives (eating a legitimate design
element or a signature block).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import fitz  # PyMuPDF

from .config import settings


@dataclass(frozen=True)
class FlaggedShape:
    page_number: int
    rect: tuple[float, float, float, float]
    fill_color: tuple[float, float, float] | None
    opacity: float
    reason: str


def _is_dark(rgb: tuple[float, float, float] | None) -> bool:
    if rgb is None:
        return False
    r, g, b = rgb
    luminance = 0.299 * r + 0.587 * g + 0.114 * b  # perceptual, 0..1
    return luminance <= settings.VECTOR_DARKNESS_THRESHOLD


def _touches_edge_band(shape_rect: fitz.Rect, page_rect: fitz.Rect, band_ratio: float) -> bool:
    band_x = page_rect.width * band_ratio
    band_y = page_rect.height * band_ratio
    near_left = shape_rect.x0 <= page_rect.x0 + band_x
    near_right = shape_rect.x1 >= page_rect.x1 - band_x
    near_top = shape_rect.y0 <= page_rect.y0 + band_y
    near_bottom = shape_rect.y1 >= page_rect.y1 - band_y
    return near_left or near_right or near_top or near_bottom


def _spans_enough(shape_rect: fitz.Rect, page_rect: fitz.Rect, min_ratio: float) -> bool:
    width_ratio = shape_rect.width / page_rect.width if page_rect.width else 0
    height_ratio = shape_rect.height / page_rect.height if page_rect.height else 0
    return width_ratio >= min_ratio or height_ratio >= min_ratio


def detect_border_shapes(page: fitz.Page) -> list[FlaggedShape]:
    """Inspect one page's drawing tree and return artifact candidates."""
    flagged: list[FlaggedShape] = []
    page_rect = page.rect

    for drawing in page.get_drawings():
        if not drawing.get("fill"):
            continue  # unfilled/stroke-only paths are never border overlays

        rect = drawing.get("rect")
        if rect is None:
            continue
        rect = fitz.Rect(rect)

        opacity = drawing.get("fill_opacity", 1.0)
        if opacity is None:
            opacity = 1.0
        if opacity < settings.VECTOR_MIN_OPACITY:
            continue

        fill_color = drawing.get("fill")  # (r, g, b) in 0..1, may be None handled above
        if not _is_dark(fill_color):
            continue

        if not _touches_edge_band(rect, page_rect, settings.VECTOR_EDGE_BAND_RATIO):
            continue

        if not _spans_enough(rect, page_rect, settings.VECTOR_MIN_SPAN_RATIO):
            continue

        flagged.append(FlaggedShape(
            page_number=page.number,
            rect=(rect.x0, rect.y0, rect.x1, rect.y1),
            fill_color=fill_color,
            opacity=opacity,
            reason="opaque dark fill spanning page edge band",
        ))

    return flagged


def _sample_background_color(page: fitz.Page, flagged: list[FlaggedShape]) -> tuple[float, float, float]:
    """
    Best-effort background estimate: render a low-res pixmap and sample a
    corner region that is NOT inside any flagged shape. Falls back to white.
    """
    try:
        pix = page.get_pixmap(matrix=fitz.Matrix(0.25, 0.25))
        page_rect = page.rect
        scale = 0.25
        candidates = [
            (page_rect.width * 0.5, page_rect.height * 0.5),  # page center
        ]
        for cx, cy in candidates:
            if any(fitz.Rect(f.rect).contains(fitz.Point(cx, cy)) for f in flagged):
                continue
            px, py = int(cx * scale), int(cy * scale)
            px = min(max(px, 0), pix.width - 1)
            py = min(max(py, 0), pix.height - 1)
            pixel = pix.pixel(px, py)
            return tuple(c / 255 for c in pixel[:3])
    except Exception:
        pass
    return (1.0, 1.0, 1.0)  # white fallback


def clean_pdf(
    sanitized_pdf_bytes: bytes,
    mode: Literal["mask", "redact"] | None = None,
) -> tuple[bytes, list[FlaggedShape]]:
    """
    Runs border-shape detection + remediation across every page.
    Returns (cleaned_pdf_bytes, all_flagged_shapes).
    """
    mode = mode or settings.VECTOR_DEFAULT_MODE
    doc = fitz.open(stream=sanitized_pdf_bytes, filetype="pdf")
    all_flagged: list[FlaggedShape] = []

    try:
        for page in doc:
            flagged = detect_border_shapes(page)
            if not flagged:
                continue
            all_flagged.extend(flagged)

            bg = _sample_background_color(page, flagged)

            if mode == "redact":
                for shape in flagged:
                    page.add_redact_annot(fitz.Rect(shape.rect), fill=bg)
                page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
            else:  # "mask" — additive, non-destructive overlay
                for shape in flagged:
                    page.draw_rect(
                        fitz.Rect(shape.rect),
                        color=bg,
                        fill=bg,
                        overlay=True,
                        width=0,
                    )

        out = doc.tobytes(garbage=3, deflate=True, clean=True)
    finally:
        doc.close()

    return out, all_flagged
