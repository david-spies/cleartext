"""
ClearText — worker/tasks.py

Background task executed per-document. Each task is fully self-contained
(receives raw bytes, returns cleaned bytes) so multi-page / multi-document
batches can fan out across workers with no shared mutable state.

Zero-retention note: the cleaned output is base64-encoded into the Celery
result backend with `result_expires` (see celery_app.py) enforcing automatic
purge. For production SaaS deployment, prefer a short-lived, encrypted
object-store entry (e.g. S3 with a bucket lifecycle rule of minutes, SSE-KMS)
over stashing payloads in Redis — swap `_store_result` / `_load_result`
for that backend without touching pipeline code.

`audit_redactions_task` below is a DISTINCT, READ-ONLY task: it never
returns a document, only a structured findings report. See
core/redaction_audit.py for the module-level safety notes on `reveal_text`.

`discover_revisions_task` / `extract_revision_task` follow the same split:
discovery is read-only and unrestricted; extraction requires explicit
`confirm_ownership=True` and is logged. See core/revision_forensics.py.
"""
from __future__ import annotations

import base64
import logging

from celery.exceptions import SoftTimeLimitExceeded

from cleartext.core.processor import ProcessingError, process_document
from cleartext.core.redaction_audit import audit_pdf
from cleartext.core.revision_forensics import discover_revisions, extract_revision
from cleartext.core.validation import (
    DocKind,
    ValidationError,
    screen_pdf_for_forensics,
    sniff_kind,
    validate_and_sanitize,
)
from .celery_app import celery_app

logger = logging.getLogger("cleartext.audit")


@celery_app.task(bind=True, name="cleartext.process_document")
def process_document_task(self, raw_b64: str, vector_mode: str, raster_mode: str) -> dict:
    try:
        raw_bytes = base64.b64decode(raw_b64)
    except Exception:
        return {"status": "failed", "error": "Corrupt upload payload."}

    try:
        result = process_document(raw_bytes, vector_mode=vector_mode, raster_mode=raster_mode)
    except ValidationError as exc:
        return {"status": "failed", "error": str(exc)}
    except SoftTimeLimitExceeded:
        return {"status": "failed", "error": "Processing exceeded the allotted time limit."}
    except ProcessingError as exc:
        return {"status": "failed", "error": str(exc)}
    except Exception:
        # Never leak internal exception details/stack traces to the client.
        return {"status": "failed", "error": "An internal processing error occurred."}

    return {
        "status": "complete",
        "kind": result.kind.value,
        "output_format": result.output_format,
        "pages_flagged": result.pages_flagged,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "output_b64": base64.b64encode(result.output_bytes).decode("ascii"),
    }


@celery_app.task(bind=True, name="cleartext.audit_redactions")
def audit_redactions_task(self, raw_b64: str, reveal_text: bool) -> dict:
    """
    Read-only redaction integrity audit. Returns a findings report only —
    never a document, never a download link. PDF-only: images have no text
    layer to audit against.
    """
    try:
        raw_bytes = base64.b64decode(raw_b64)
    except Exception:
        return {"status": "failed", "error": "Corrupt upload payload."}

    try:
        kind = sniff_kind(raw_bytes)
        if kind is not DocKind.PDF:
            return {
                "status": "failed",
                "error": "Redaction audit only supports PDF documents (no text layer exists to check in a raster image).",
            }
        validated = validate_and_sanitize(raw_bytes)
        report = audit_pdf(validated.sanitized_bytes, reveal_text=reveal_text)
    except ValidationError as exc:
        return {"status": "failed", "error": str(exc)}
    except SoftTimeLimitExceeded:
        return {"status": "failed", "error": "Audit exceeded the allotted time limit."}
    except Exception:
        return {"status": "failed", "error": "An internal audit error occurred."}

    return {
        "status": "complete",
        "pages_audited": report.pages_audited,
        "total_boxes_found": report.total_boxes_found,
        "critical_count": report.critical_count,
        "clear_count": report.clear_count,
        "summary": report.summary,
        "findings": [
            {
                "page_number": f.page_number,
                "rect": f.rect,
                "source": f.source.value,
                "risk_level": f.risk_level.value,
                "underlying_word_count": f.underlying_word_count,
                "underlying_char_count": f.underlying_char_count,
                "note": f.note,
                "revealed_text": f.revealed_text,
            }
            for f in report.findings
        ],
    }


@celery_app.task(bind=True, name="cleartext.discover_revisions")
def discover_revisions_task(self, raw_b64: str) -> dict:
    """
    Read-only. Screens for malicious content WITHOUT rebuilding the PDF
    (see validation.screen_pdf_for_forensics — a full validate_and_sanitize
    rebuild would collapse the very incremental-save history this looks
    for), then reports structural facts about each discovered revision.
    Never returns document content.
    """
    try:
        raw_bytes = base64.b64decode(raw_b64)
    except Exception:
        return {"status": "failed", "error": "Corrupt upload payload."}

    try:
        screen_pdf_for_forensics(raw_bytes)
        report = discover_revisions(raw_bytes)
    except ValidationError as exc:
        return {"status": "failed", "error": str(exc)}
    except SoftTimeLimitExceeded:
        return {"status": "failed", "error": "Discovery exceeded the allotted time limit."}
    except Exception:
        return {"status": "failed", "error": "An internal discovery error occurred."}

    return {
        "status": "complete",
        "total_revisions_found": report.total_revisions_found,
        "pages_in_current_revision": report.pages_in_current_revision,
        "summary": report.summary,
        "truncated": report.truncated,
        "revisions": [
            {
                "revision_index": r.revision_index,
                "size_bytes": r.size_bytes,
                "is_current": r.is_current,
                "page_count": r.page_count,
                "object_count": r.object_count,
                "creation_date": r.creation_date,
                "mod_date": r.mod_date,
                "openable": r.openable,
                "note": r.note,
            }
            for r in report.revisions
        ],
    }


@celery_app.task(bind=True, name="cleartext.extract_revision")
def extract_revision_task(self, raw_b64: str, revision_index: int, confirm_ownership: bool) -> dict:
    """
    GATED. Requires confirm_ownership=True — the API layer rejects the
    request before even queuing this task if that flag isn't set, but the
    check is repeated here as defense in depth. Every call is logged
    (task id, revision index) for audit purposes; see the warning in
    core/revision_forensics.py.extract_revision().
    """
    if not confirm_ownership:
        return {"status": "failed", "error": "confirm_ownership must be true to extract a historical revision."}

    logger.info(
        "revision extraction requested: task_id=%s revision_index=%s",
        self.request.id, revision_index,
    )

    try:
        raw_bytes = base64.b64decode(raw_b64)
    except Exception:
        return {"status": "failed", "error": "Corrupt upload payload."}

    try:
        extracted_bytes = extract_revision(raw_bytes, revision_index, confirm_ownership=True)
    except ValueError as exc:
        return {"status": "failed", "error": str(exc)}
    except ValidationError as exc:
        return {
            "status": "failed",
            "error": f"Historical revision failed exploit screening and cannot be released: {exc}",
        }
    except SoftTimeLimitExceeded:
        return {"status": "failed", "error": "Extraction exceeded the allotted time limit."}
    except Exception:
        return {"status": "failed", "error": "An internal extraction error occurred."}

    logger.info(
        "revision extraction completed: task_id=%s revision_index=%s output_bytes=%d",
        self.request.id, revision_index, len(extracted_bytes),
    )

    return {
        "status": "complete",
        "revision_index": revision_index,
        "output_b64": base64.b64encode(extracted_bytes).decode("ascii"),
    }
