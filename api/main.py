"""
ClearText — api/main.py

FastAPI service layer. Two-phase async flow keeps the HTTP request cycle
lightweight for large/multi-page documents:

  POST /api/v1/documents          -> validates + enqueues -> 202 + job_id
  GET  /api/v1/documents/{job_id} -> poll status, get short-lived download link
  GET  /api/v1/documents/{job_id}/download -> streams cleaned bytes once,
                                                then the result is gone.

Security posture at this layer:
  - Upload size is rejected at the ASGI layer before the body is fully
    buffered (Content-Length pre-check) as well as re-checked after read.
  - No file is ever written under a client-controlled name/path.
  - CORS is locked down to configured origins only — tighten for prod.
  - Every unhandled exception is caught and mapped to a generic 500; no
    stack traces or internal paths are ever returned to the client.
"""
from __future__ import annotations

import base64
import os
import uuid

from typing import Annotated, Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from cleartext.core.config import settings
from cleartext.core.validation import ValidationError
from cleartext.worker.celery_app import celery_app
from cleartext.worker.tasks import (
    audit_redactions_task,
    discover_revisions_task,
    extract_revision_task,
    process_document_task,
)

from .schemas import (
    JobStatusResponse,
    JobSubmitResponse,
    RedactionAuditJobStatusResponse,
    RedactionFindingResponse,
    RevisionDiscoveryJobStatusResponse,
    RevisionExtractionJobStatusResponse,
    RevisionMetadataResponse,
)

app = FastAPI(
    title="ClearText API",
    description="Universal document border/artifact removal — zero-retention processing.",
    version="1.0.0",
)

ALLOWED_ORIGINS = os.environ.get("CT_ALLOWED_ORIGINS", "").split(",") if os.environ.get("CT_ALLOWED_ORIGINS") else []

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class ContentLengthGuard(BaseHTTPMiddleware):
    """Rejects oversized uploads before the body is buffered into memory."""

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > settings.MAX_UPLOAD_BYTES:
                return Response(
                    content='{"detail":"File exceeds maximum allowed size."}',
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    media_type="application/json",
                )
        return await call_next(request)


app.add_middleware(ContentLengthGuard)


@app.get("/", include_in_schema=False)
async def root():
    """Convenience redirect — no UI lives at the bare root, just the API."""
    return RedirectResponse(url="/docs")


@app.get("/healthz", tags=["ops"])
async def healthz():
    return {"status": "ok"}


@app.post(
    "/api/v1/documents",
    response_model=JobSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["documents"],
)
async def submit_document(
    file: UploadFile = File(...),
    vector_mode: Annotated[
        Literal["mask", "redact"],
        Form(description="Remediation strategy for digital PDF border shapes."),
    ] = "mask",
    raster_mode: Annotated[
        Literal["crop", "paint"],
        Form(description="Remediation strategy for scanned image border artifacts."),
    ] = "paint",
):
    raw = await file.read()
    if len(raw) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds maximum allowed size.")

    # Fail fast on obviously-bad input synchronously so the client gets an
    # immediate 400 instead of polling a job that was doomed at submission.
    # Full sanitization still re-runs inside the worker (defense in depth —
    # never trust a check performed in a different process/trust boundary
    # than the one that will act on the result).
    try:
        from cleartext.core.validation import sniff_kind
        sniff_kind(raw)
    except ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    raw_b64 = base64.b64encode(raw).decode("ascii")
    async_result = process_document_task.delay(raw_b64, vector_mode, raster_mode)

    return JobSubmitResponse(
        job_id=async_result.id,
        status="queued",
        poll_url=f"/api/v1/documents/{async_result.id}",
    )


@app.get(
    "/api/v1/documents/{job_id}",
    response_model=JobStatusResponse,
    tags=["documents"],
)
async def get_job_status(job_id: str):
    async_result = celery_app.AsyncResult(job_id)

    if async_result.state in ("PENDING", "STARTED", "RETRY"):
        return JobStatusResponse(
            job_id=job_id,
            status="processing" if async_result.state == "STARTED" else "queued",
        )

    if async_result.state == "FAILURE":
        return JobStatusResponse(job_id=job_id, status="failed", error="Internal processing error.")

    if async_result.state == "SUCCESS":
        payload = async_result.result or {}
        if payload.get("status") == "failed":
            return JobStatusResponse(job_id=job_id, status="failed", error=payload.get("error"))

        return JobStatusResponse(
            job_id=job_id,
            status="complete",
            kind=payload.get("kind"),
            pages_flagged=payload.get("pages_flagged"),
            elapsed_seconds=payload.get("elapsed_seconds"),
            download_url=f"/api/v1/documents/{job_id}/download",
            expires_in_seconds=settings.JOB_TTL_SECONDS,
        )

    return JobStatusResponse(job_id=job_id, status="queued")


@app.get("/api/v1/documents/{job_id}/download", tags=["documents"])
async def download_result(job_id: str):
    async_result = celery_app.AsyncResult(job_id)
    if async_result.state != "SUCCESS":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not ready or not found.")

    payload = async_result.result or {}
    if payload.get("status") != "complete":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not available.")

    output_bytes = base64.b64decode(payload["output_b64"])
    fmt = payload["output_format"]
    media_types = {
        "pdf": "application/pdf",
        "png": "image/png",
        "jpeg": "image/jpeg",
        "tiff": "image/tiff",
    }

    # Zero-retention: forget the result the instant it's been fetched once,
    # rather than waiting out the full TTL window.
    async_result.forget()

    return Response(
        content=output_bytes,
        media_type=media_types.get(fmt, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="cleartext_output.{fmt}"'},
    )


# =============================================================================
# Redaction integrity audit — a DISTINCT, READ-ONLY feature.
#
# This never modifies or returns a document. It only reports whether opaque
# boxes on a PDF page have extractable text underneath them — i.e. whether a
# redaction actually removed content or just painted over it. There is no
# download endpoint here on purpose: the output is a findings report, never
# a file.
#
# `reveal_text` defaults to False and must be explicitly opted into by the
# caller. When True, CRITICAL findings include the actual text hidden under
# a failed redaction box. This should only ever be set True by a document's
# own owner performing remediation on their own file — never expose it as a
# default in a client UI, and never call it in an unattended/batch context
# without that same guarantee. See core/redaction_audit.py for the full
# rationale.
# =============================================================================


@app.post(
    "/api/v1/audit/redactions",
    response_model=JobSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["redaction-audit"],
    summary="Submit a PDF for a read-only redaction integrity audit",
)
async def submit_redaction_audit(
    file: UploadFile = File(...),
    reveal_text: Annotated[
        bool,
        Form(
            description=(
                "WARNING: only enable this if you are the document's own owner "
                "performing remediation. When true, CRITICAL findings include the "
                "actual text found hidden under a failed redaction box."
            )
        ),
    ] = False,
):
    raw = await file.read()
    if len(raw) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds maximum allowed size.")

    try:
        from cleartext.core.validation import DocKind, sniff_kind
        kind = sniff_kind(raw)
        if kind is not DocKind.PDF:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Redaction audit only supports PDF documents — a raster image has no text layer to check.",
            )
    except ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    raw_b64 = base64.b64encode(raw).decode("ascii")
    async_result = audit_redactions_task.delay(raw_b64, reveal_text)

    return JobSubmitResponse(
        job_id=async_result.id,
        status="queued",
        poll_url=f"/api/v1/audit/redactions/{async_result.id}",
    )


@app.get(
    "/api/v1/audit/redactions/{job_id}",
    response_model=RedactionAuditJobStatusResponse,
    tags=["redaction-audit"],
    summary="Poll a redaction audit job and retrieve its findings report",
)
async def get_redaction_audit_status(job_id: str):
    async_result = celery_app.AsyncResult(job_id)

    if async_result.state in ("PENDING", "STARTED", "RETRY"):
        return RedactionAuditJobStatusResponse(
            job_id=job_id,
            status="processing" if async_result.state == "STARTED" else "queued",
        )

    if async_result.state == "FAILURE":
        return RedactionAuditJobStatusResponse(job_id=job_id, status="failed", error="Internal audit error.")

    if async_result.state == "SUCCESS":
        payload = async_result.result or {}
        if payload.get("status") == "failed":
            return RedactionAuditJobStatusResponse(job_id=job_id, status="failed", error=payload.get("error"))

        response = RedactionAuditJobStatusResponse(
            job_id=job_id,
            status="complete",
            pages_audited=payload.get("pages_audited"),
            total_boxes_found=payload.get("total_boxes_found"),
            critical_count=payload.get("critical_count"),
            clear_count=payload.get("clear_count"),
            summary=payload.get("summary"),
            findings=[RedactionFindingResponse(**f) for f in payload.get("findings", [])],
        )

        # Zero-retention applies here too, including any revealed text.
        async_result.forget()
        return response

    return RedactionAuditJobStatusResponse(job_id=job_id, status="queued")


# =============================================================================
# Revision forensics — discovery is open and read-only; extraction of an
# actual historical revision is a DISTINCT, EXPLICITLY-GATED action.
#
# Discovery never returns document content — only structural facts (revision
# count, sizes, timestamps) sufficient to answer "does this PDF leak
# incremental-save history?" without becoming a general-purpose recovery
# tool. Extraction requires the caller to explicitly set
# confirm_ownership=True and re-submit the file (results from the discovery
# job are not cached/reusable for extraction — this pipeline keeps no state
# between jobs by design, and re-submission is itself a small amount of
# deliberate friction rather than a one-click follow-on action).
#
# See core/revision_forensics.py for the full rationale and the warning on
# extract_revision().
# =============================================================================


@app.post(
    "/api/v1/forensics/revisions",
    response_model=JobSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["revision-forensics"],
    summary="Submit a PDF to discover incremental-save revision history (read-only)",
)
async def submit_revision_discovery(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds maximum allowed size.")

    try:
        from cleartext.core.validation import DocKind, sniff_kind
        kind = sniff_kind(raw)
        if kind is not DocKind.PDF:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Revision forensics only supports PDF documents.",
            )
    except ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    raw_b64 = base64.b64encode(raw).decode("ascii")
    async_result = discover_revisions_task.delay(raw_b64)

    return JobSubmitResponse(
        job_id=async_result.id,
        status="queued",
        poll_url=f"/api/v1/forensics/revisions/{async_result.id}",
    )


@app.get(
    "/api/v1/forensics/revisions/{job_id}",
    response_model=RevisionDiscoveryJobStatusResponse,
    tags=["revision-forensics"],
    summary="Poll a revision discovery job and retrieve the revision timeline",
)
async def get_revision_discovery_status(job_id: str):
    async_result = celery_app.AsyncResult(job_id)

    if async_result.state in ("PENDING", "STARTED", "RETRY"):
        return RevisionDiscoveryJobStatusResponse(
            job_id=job_id,
            status="processing" if async_result.state == "STARTED" else "queued",
        )

    if async_result.state == "FAILURE":
        return RevisionDiscoveryJobStatusResponse(job_id=job_id, status="failed", error="Internal discovery error.")

    if async_result.state == "SUCCESS":
        payload = async_result.result or {}
        if payload.get("status") == "failed":
            return RevisionDiscoveryJobStatusResponse(job_id=job_id, status="failed", error=payload.get("error"))

        response = RevisionDiscoveryJobStatusResponse(
            job_id=job_id,
            status="complete",
            total_revisions_found=payload.get("total_revisions_found"),
            pages_in_current_revision=payload.get("pages_in_current_revision"),
            summary=payload.get("summary"),
            truncated=payload.get("truncated"),
            revisions=[RevisionMetadataResponse(**r) for r in payload.get("revisions", [])],
        )
        async_result.forget()
        return response

    return RevisionDiscoveryJobStatusResponse(job_id=job_id, status="queued")


@app.post(
    "/api/v1/forensics/revisions/extract",
    response_model=JobSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["revision-forensics"],
    summary="GATED — extract one historical revision as a standalone PDF",
)
async def submit_revision_extraction(
    file: UploadFile = File(...),
    revision_index: Annotated[
        int,
        Form(description="1-based revision index from a prior discovery job's report (1 = oldest)."),
    ] = 1,
    confirm_ownership: Annotated[
        bool,
        Form(
            description=(
                "REQUIRED. Must be explicitly set true. This confirms the caller is the "
                "document's own owner/custodian performing remediation — never set this "
                "true on behalf of a document you did not author or are not authorized "
                "to fully inspect. This action is logged."
            )
        ),
    ] = False,
):
    if not confirm_ownership:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "confirm_ownership must be explicitly set to true to extract a historical revision. "
            "This is a deliberate gate, not an oversight — see the API documentation.",
        )

    raw = await file.read()
    if len(raw) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds maximum allowed size.")

    try:
        from cleartext.core.validation import DocKind, sniff_kind
        kind = sniff_kind(raw)
        if kind is not DocKind.PDF:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Revision forensics only supports PDF documents.")
    except ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    if revision_index < 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "revision_index must be 1 or greater.")

    raw_b64 = base64.b64encode(raw).decode("ascii")
    async_result = extract_revision_task.delay(raw_b64, revision_index, confirm_ownership)

    return JobSubmitResponse(
        job_id=async_result.id,
        status="queued",
        poll_url=f"/api/v1/forensics/revisions/extract/{async_result.id}",
    )


@app.get(
    "/api/v1/forensics/revisions/extract/{job_id}",
    response_model=RevisionExtractionJobStatusResponse,
    tags=["revision-forensics"],
    summary="Poll a gated revision extraction job",
)
async def get_revision_extraction_status(job_id: str):
    async_result = celery_app.AsyncResult(job_id)

    if async_result.state in ("PENDING", "STARTED", "RETRY"):
        return RevisionExtractionJobStatusResponse(
            job_id=job_id,
            status="processing" if async_result.state == "STARTED" else "queued",
        )

    if async_result.state == "FAILURE":
        return RevisionExtractionJobStatusResponse(job_id=job_id, status="failed", error="Internal extraction error.")

    if async_result.state == "SUCCESS":
        payload = async_result.result or {}
        if payload.get("status") == "failed":
            return RevisionExtractionJobStatusResponse(job_id=job_id, status="failed", error=payload.get("error"))

        return RevisionExtractionJobStatusResponse(
            job_id=job_id,
            status="complete",
            revision_index=payload.get("revision_index"),
            download_url=f"/api/v1/forensics/revisions/extract/{job_id}/download",
            expires_in_seconds=settings.JOB_TTL_SECONDS,
        )

    return RevisionExtractionJobStatusResponse(job_id=job_id, status="queued")


@app.get(
    "/api/v1/forensics/revisions/extract/{job_id}/download",
    tags=["revision-forensics"],
    summary="Download an extracted historical revision (one-time)",
)
async def download_extracted_revision(job_id: str):
    async_result = celery_app.AsyncResult(job_id)
    if async_result.state != "SUCCESS":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not ready or not found.")

    payload = async_result.result or {}
    if payload.get("status") != "complete":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Result not available.")

    output_bytes = base64.b64decode(payload["output_b64"])
    revision_index = payload.get("revision_index", "unknown")

    async_result.forget()

    return Response(
        content=output_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cleartext_revision_{revision_index}.pdf"'},
    )
