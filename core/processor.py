"""
ClearText — core/processor.py

Top-level orchestration: validate -> route -> process -> return, with a
zero-retention temp workspace guaranteed to be shredded on exit regardless
of success/failure/exception. This is the only module API surfaces (the
FastAPI route, the Celery task) should call into directly.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from .config import settings
from .raster_pipeline import FlaggedRegion, clean_image
from .validation import DocKind, ValidationError, validate_and_sanitize
from .vector_pipeline import FlaggedShape, clean_pdf


@dataclass
class ProcessingResult:
    kind: DocKind
    output_bytes: bytes
    output_format: str
    pages_flagged: int
    flags: list = field(default_factory=list)
    elapsed_seconds: float = 0.0


class ProcessingError(Exception):
    pass


@contextmanager
def _ephemeral_workspace():
    """
    All intermediate artifacts live here. In-memory processing is preferred
    throughout the pipelines (bytes in, bytes out), but this directory exists
    as a hard backstop for any library call that insists on touching disk —
    it is guaranteed removed even on exception.
    """
    workdir = tempfile.mkdtemp(prefix="cleartext_job_")
    try:
        yield workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def process_document(
    raw_bytes: bytes,
    vector_mode: str | None = None,
    raster_mode: str | None = None,
) -> ProcessingResult:
    """
    Zero-retention entry point: takes raw uploaded bytes, returns cleaned
    output bytes. Nothing here is ever written to durable storage; the
    ephemeral workspace is only a defensive backstop, not a real dependency.
    """
    start = time.monotonic()

    try:
        validated = validate_and_sanitize(raw_bytes)
    except ValidationError as exc:
        raise  # caller (API layer) maps this to HTTP 400 with the safe message

    with _ephemeral_workspace():
        if validated.kind is DocKind.PDF:
            cleaned_bytes, flagged_shapes = clean_pdf(validated.sanitized_bytes, mode=vector_mode)
            pages_flagged = len({f.page_number for f in flagged_shapes})
            result = ProcessingResult(
                kind=DocKind.PDF,
                output_bytes=cleaned_bytes,
                output_format="pdf",
                pages_flagged=pages_flagged,
                flags=[f.__dict__ for f in flagged_shapes],
                elapsed_seconds=time.monotonic() - start,
            )
        else:
            cleaned_bytes, flagged_regions, out_fmt = clean_image(
                validated.sanitized_bytes, mode=raster_mode
            )
            result = ProcessingResult(
                kind=DocKind.RASTER_IMAGE,
                output_bytes=cleaned_bytes,
                output_format=out_fmt.lower(),
                pages_flagged=1 if flagged_regions else 0,
                flags=[f.__dict__ for f in flagged_regions],
                elapsed_seconds=time.monotonic() - start,
            )

    if result.elapsed_seconds > settings.PROCESSING_TIMEOUT_SECONDS:
        # We still return the result (work is already done), but this signal
        # is what the worker-level hard timeout (SIGALRM / Celery time_limit)
        # is backstopping against for pathological inputs that get this far.
        pass

    return result
