"""
ClearText — core/config.py

Centralized, environment-overridable configuration. Nothing in the pipelines
should hardcode a magic number that belongs here — this file is the single
tuning surface for security limits and CV/vector detection thresholds.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # ---- Hard security limits -------------------------------------------------
    MAX_UPLOAD_BYTES: int = _env_int("CT_MAX_UPLOAD_BYTES", 50 * 1024 * 1024)  # 50MB
    MAX_PDF_PAGES: int = _env_int("CT_MAX_PDF_PAGES", 500)
    MAX_PDF_OBJECTS: int = _env_int("CT_MAX_PDF_OBJECTS", 250_000)
    MAX_PDF_NEST_DEPTH: int = _env_int("CT_MAX_PDF_NEST_DEPTH", 24)
    MAX_IMAGE_PIXELS: int = _env_int("CT_MAX_IMAGE_PIXELS", 64_000_000)  # ~64MP decompression-bomb guard
    MAX_IMAGE_DIMENSION: int = _env_int("CT_MAX_IMAGE_DIMENSION", 12_000)  # px, per side
    PROCESSING_TIMEOUT_SECONDS: int = _env_int("CT_PROCESSING_TIMEOUT_SECONDS", 90)

    # ---- Zero-retention behavior -----------------------------------------------
    JOB_TTL_SECONDS: int = _env_int("CT_JOB_TTL_SECONDS", 900)  # result purge window
    PERSIST_TO_DISK: bool = _env_bool("CT_PERSIST_TO_DISK", False)  # should stay False in prod

    # ---- Vector pipeline (digital PDFs) ----------------------------------------
    # A drawn rectangle is a "border candidate" if it sits within this fraction
    # of the page's outer edge...
    VECTOR_EDGE_BAND_RATIO: float = _env_float("CT_VECTOR_EDGE_BAND_RATIO", 0.12)
    # ...AND covers at least this fraction of the page's width or height...
    VECTOR_MIN_SPAN_RATIO: float = _env_float("CT_VECTOR_MIN_SPAN_RATIO", 0.55)
    # ...AND is opaque-ish (alpha threshold, 1.0 = fully opaque).
    VECTOR_MIN_OPACITY: float = _env_float("CT_VECTOR_MIN_OPACITY", 0.85)
    # Fill color must be "dark" (near-black) to qualify as an artifact by default.
    VECTOR_DARKNESS_THRESHOLD: float = _env_float("CT_VECTOR_DARKNESS_THRESHOLD", 0.25)
    # Default remediation mode: "mask" (non-destructive overlay) or "redact"
    # (true content-stream removal via PyMuPDF redaction — more aggressive).
    VECTOR_DEFAULT_MODE: str = os.environ.get("CT_VECTOR_DEFAULT_MODE", "mask")

    # ---- Raster pipeline (scanned images) --------------------------------------
    RASTER_BINARIZE_BLOCK_SIZE: int = _env_int("CT_RASTER_BLOCK_SIZE", 41)  # must be odd
    RASTER_BINARIZE_C: int = _env_int("CT_RASTER_BINARIZE_C", 15)
    RASTER_CANNY_LOW: int = _env_int("CT_RASTER_CANNY_LOW", 50)
    RASTER_CANNY_HIGH: int = _env_int("CT_RASTER_CANNY_HIGH", 150)
    # A contour is a border-bar candidate if it spans at least this much of the
    # image's width/height along its short axis is thin relative to the page.
    RASTER_MIN_SPAN_RATIO: float = _env_float("CT_RASTER_MIN_SPAN_RATIO", 0.5)
    RASTER_MAX_THICKNESS_RATIO: float = _env_float("CT_RASTER_MAX_THICKNESS_RATIO", 0.22)
    RASTER_MEAN_INTENSITY_MAX: int = _env_int("CT_RASTER_MEAN_INTENSITY_MAX", 60)  # 0-255
    # Remediation: "crop" removes the artifact band entirely (only safe when
    # it's a true page-edge margin), "paint" inpaints/fills with sampled bg color.
    RASTER_DEFAULT_MODE: str = os.environ.get("CT_RASTER_DEFAULT_MODE", "paint")

    # ---- Redaction integrity audit (read-only) ---------------------------------
    # Deliberately DIFFERENT tuning from the vector border detector above:
    # redaction boxes are typically small and localized anywhere on the page,
    # not edge-spanning, so there is no edge-band or min-span-ratio gate here.
    AUDIT_MIN_OPACITY: float = _env_float("CT_AUDIT_MIN_OPACITY", 0.85)
    # Redaction boxes are usually solid black, but some tools use white, gray,
    # or a brand color. Default only flags dark fills to keep noise down;
    # widen AUDIT_DARKNESS_THRESHOLD or set AUDIT_ANY_SOLID_COLOR to broaden.
    AUDIT_DARKNESS_THRESHOLD: float = _env_float("CT_AUDIT_DARKNESS_THRESHOLD", 0.30)
    AUDIT_ANY_SOLID_COLOR: bool = _env_bool("CT_AUDIT_ANY_SOLID_COLOR", False)
    # Ignore tiny shapes (bullets, checkboxes, icons) and near-full-page fills
    # (legitimate background rectangles), as fractions of total page area.
    AUDIT_MIN_BOX_AREA_RATIO: float = _env_float("CT_AUDIT_MIN_BOX_AREA_RATIO", 0.0008)
    AUDIT_MAX_BOX_AREA_RATIO: float = _env_float("CT_AUDIT_MAX_BOX_AREA_RATIO", 0.85)
    # Image-overlay detection: an embedded image is a redaction-box candidate
    # if its rendered footprint is this uniform in color (0 = solid, 1 = noisy).
    AUDIT_IMAGE_COLOR_VARIANCE_MAX: float = _env_float("CT_AUDIT_IMAGE_COLOR_VARIANCE_MAX", 12.0)

    # ---- Revision forensics (discovery is read-only; extraction is gated) ------
    # Caps guard against a pathological/hostile PDF engineered with thousands
    # of tiny incremental updates (or byte sequences crafted to resemble
    # revision boundaries) turning a single upload into an expensive
    # open()-and-validate loop — a DoS vector distinct from the decompression
    # bombs the raster/PDF validators already guard against.
    FORENSICS_MAX_BOUNDARY_CANDIDATES: int = _env_int("CT_FORENSICS_MAX_BOUNDARY_CANDIDATES", 200)
    FORENSICS_MAX_REVISIONS_REPORTED: int = _env_int("CT_FORENSICS_MAX_REVISIONS_REPORTED", 50)
    # Revisions below this size are almost certainly boundary false-positives
    # (a coincidental byte sequence resembling "startxref N %%EOF" inside a
    # compressed stream) rather than a real, independently-openable document.
    FORENSICS_MIN_REVISION_BYTES: int = _env_int("CT_FORENSICS_MIN_REVISION_BYTES", 64)

    ALLOWED_MIME_TYPES: tuple = field(default_factory=lambda: (
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/tiff",
    ))


settings = Settings()
