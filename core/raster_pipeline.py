"""
ClearText — core/raster_pipeline.py

Handles scanned/flattened raster documents (PNG, JPEG, TIFF): finds solid
black scanner-bed margins and side bars via classical CV (adaptive
binarization -> Canny edges -> contour analysis) and either crops them off
(when they're true page-edge margins) or paints over them with a sampled
background color (safer default — works even when the artifact isn't
perfectly axis-aligned to the crop boundary).

Pipeline stages:
  1. Decode -> grayscale.
  2. Adaptive threshold (handles uneven scanner illumination better than a
     single global threshold).
  3. Canny edge map + contour extraction on the binarized image.
  4. Filter contours to "border-bar" candidates: thin relative to the page,
     long relative to the page, low mean intensity (i.e., actually black,
     not just an edge outline).
  5. Merge overlapping/adjacent candidate boxes per side (left/right/top/
     bottom) into a single margin band.
  6. Remediate: crop (if the band touches the image boundary) or inpaint/
     flood-fill with sampled background color.
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Literal

import cv2
import numpy as np
from PIL import Image

from .config import settings


@dataclass(frozen=True)
class FlaggedRegion:
    x: int
    y: int
    w: int
    h: int
    side: str  # "left" | "right" | "top" | "bottom" | "interior"
    mean_intensity: float


def _load_bgr(raw: bytes) -> np.ndarray:
    pil_img = Image.open(io.BytesIO(raw)).convert("RGB")
    arr = np.array(pil_img)
    return cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)


def _binarize(gray: np.ndarray) -> np.ndarray:
    """
    Adaptive threshold — good for isolating text/fine strokes under uneven
    scanner illumination. NOT used as the primary signal for solid margin
    bars: a large uniform-black region looks "locally normal" relative to
    its own neighborhood, so adaptive thresholding alone systematically
    misses the interior of wide bars. Kept here for potential future
    text/foreground-aware refinements layered on top of the darkness mask.
    """
    block = settings.RASTER_BINARIZE_BLOCK_SIZE
    if block % 2 == 0:
        block += 1
    return cv2.adaptiveThreshold(
        gray, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY_INV,
        block,
        settings.RASTER_BINARIZE_C,
    )


def _darkness_mask(gray: np.ndarray) -> np.ndarray:
    """
    Absolute-intensity mask: a scanner bar is genuinely dark in absolute
    terms, not merely dark relative to its neighbors. This is the correct
    primary signal for solid-fill margin/bar detection, and is robust to
    bars wider than the adaptive-threshold block size.
    """
    _, mask = cv2.threshold(gray, settings.RASTER_MEAN_INTENSITY_MAX, 255, cv2.THRESH_BINARY_INV)
    return mask


def _classify_side(x, y, w, h, img_w, img_h) -> str:
    edge_tol = 0.03
    if x <= img_w * edge_tol:
        return "left"
    if x + w >= img_w * (1 - edge_tol):
        return "right"
    if y <= img_h * edge_tol:
        return "top"
    if y + h >= img_h * (1 - edge_tol):
        return "bottom"
    return "interior"


def _has_crisp_inner_boundary(
    edges: np.ndarray, x: int, y: int, cw: int, ch: int, side: str, img_w: int, img_h: int,
    band_px: int = 5, min_edge_fraction: float = 0.05,
) -> bool:
    """
    A genuine scanner bar transitions sharply into the page content; a soft
    vignette or JPEG-gradient shadow does not. Sample a thin band along the
    contour's interior-facing edge and require meaningful Canny edge density
    there, distinguishing real artifacts from gradual lighting falloff.
    """
    if side == "left":
        band = edges[y:y + ch, max(0, x + cw - band_px):x + cw + band_px]
    elif side == "right":
        band = edges[y:y + ch, max(0, x - band_px):min(img_w, x + band_px)]
    elif side == "top":
        band = edges[max(0, y + ch - band_px):y + ch + band_px, x:x + cw]
    else:  # bottom
        band = edges[max(0, y - band_px):min(img_h, y + band_px), x:x + cw]

    if band.size == 0:
        return False
    edge_fraction = float(np.count_nonzero(band)) / band.size
    return edge_fraction >= min_edge_fraction


def detect_border_regions(bgr: np.ndarray) -> list[FlaggedRegion]:
    h, w = bgr.shape[:2]
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)

    # Primary signal: absolute darkness mask (see _darkness_mask docstring —
    # adaptive thresholding alone misses the interior of wide uniform bars).
    dark_mask = _darkness_mask(gray)
    kernel = np.ones((5, 5), np.uint8)
    dark_mask = cv2.morphologyEx(dark_mask, cv2.MORPH_CLOSE, kernel, iterations=2)

    # Edge map is used as a *confirmation* signal (a real scanner bar has a
    # crisp, high-contrast boundary against the page content) to reject soft
    # vignettes/gradients that happen to be dark but fade in gradually.
    edges = cv2.Canny(gray, settings.RASTER_CANNY_LOW, settings.RASTER_CANNY_HIGH)

    contours, _ = cv2.findContours(dark_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    flagged: list[FlaggedRegion] = []
    for cnt in contours:
        x, y, cw, ch = cv2.boundingRect(cnt)
        side = _classify_side(x, y, cw, ch, w, h)
        if side == "interior":
            continue  # only page-edge artifacts are in scope for this pipeline

        span_ratio = (ch / h) if side in ("left", "right") else (cw / w)
        thickness_ratio = (cw / w) if side in ("left", "right") else (ch / h)

        if span_ratio < settings.RASTER_MIN_SPAN_RATIO:
            continue
        if thickness_ratio > settings.RASTER_MAX_THICKNESS_RATIO:
            continue  # too thick to be a margin bar — likely real content

        roi = gray[y:y + ch, x:x + cw]
        if roi.size == 0:
            continue
        mean_intensity = float(roi.mean())
        if mean_intensity > settings.RASTER_MEAN_INTENSITY_MAX:
            continue  # not actually dark enough to be a black bar

        if not _has_crisp_inner_boundary(edges, x, y, cw, ch, side, w, h):
            continue  # gradual vignette/shadow, not a genuine hard-edged bar

        flagged.append(FlaggedRegion(x=x, y=y, w=cw, h=ch, side=side, mean_intensity=mean_intensity))

    return _merge_by_side(flagged, w, h)


def _merge_by_side(regions: list[FlaggedRegion], img_w: int, img_h: int) -> list[FlaggedRegion]:
    """Collapse multiple overlapping detections per side into one band."""
    merged: list[FlaggedRegion] = []
    for side in ("left", "right", "top", "bottom"):
        side_regions = [r for r in regions if r.side == side]
        if not side_regions:
            continue
        if side in ("left", "right"):
            max_extent = max(r.x + r.w for r in side_regions) if side == "left" else img_w - min(r.x for r in side_regions)
            x0 = 0 if side == "left" else img_w - max_extent
            merged.append(FlaggedRegion(
                x=x0, y=0, w=max_extent, h=img_h, side=side,
                mean_intensity=float(np.mean([r.mean_intensity for r in side_regions])),
            ))
        else:
            max_extent = max(r.y + r.h for r in side_regions) if side == "top" else img_h - min(r.y for r in side_regions)
            y0 = 0 if side == "top" else img_h - max_extent
            merged.append(FlaggedRegion(
                x=0, y=y0, w=img_w, h=max_extent, side=side,
                mean_intensity=float(np.mean([r.mean_intensity for r in side_regions])),
            ))
    return merged


def _sample_background_color(bgr: np.ndarray, flagged: list[FlaggedRegion]) -> tuple[int, int, int]:
    h, w = bgr.shape[:2]
    mask = np.zeros((h, w), dtype=bool)
    for r in flagged:
        mask[r.y:r.y + r.h, r.x:r.x + r.w] = True
    interior = bgr[~mask]
    if interior.size == 0:
        return (255, 255, 255)
    # Median is robust to any residual dark pixels (text) inside the sample.
    b, g, r = np.median(interior, axis=0)
    return (int(b), int(g), int(r))


def clean_image(
    sanitized_image_bytes: bytes,
    mode: Literal["crop", "paint"] | None = None,
) -> tuple[bytes, list[FlaggedRegion], str]:
    """
    Returns (cleaned_image_bytes, flagged_regions, output_format).
    """
    mode = mode or settings.RASTER_DEFAULT_MODE
    pil_img = Image.open(io.BytesIO(sanitized_image_bytes))
    out_format = pil_img.format or "PNG"
    bgr = _load_bgr(sanitized_image_bytes)

    flagged = detect_border_regions(bgr)
    if not flagged:
        return sanitized_image_bytes, [], out_format

    if mode == "crop":
        h, w = bgr.shape[:2]
        top = next((r.h for r in flagged if r.side == "top"), 0)
        bottom = next((r.h for r in flagged if r.side == "bottom"), 0)
        left = next((r.w for r in flagged if r.side == "left"), 0)
        right = next((r.w for r in flagged if r.side == "right"), 0)
        cropped = bgr[top:h - bottom, left:w - right]
        result = cropped
    else:  # "paint"
        bg = _sample_background_color(bgr, flagged)
        result = bgr.copy()
        for r in flagged:
            cv2.rectangle(result, (r.x, r.y), (r.x + r.w, r.y + r.h), bg, thickness=-1)

    rgb = cv2.cvtColor(result, cv2.COLOR_BGR2RGB)
    out_pil = Image.fromarray(rgb)
    buf = io.BytesIO()
    save_format = "PNG" if out_format not in ("PNG", "JPEG", "TIFF") else out_format
    out_pil.save(buf, format=save_format)
    return buf.getvalue(), flagged, save_format
