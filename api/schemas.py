from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class JobSubmitResponse(BaseModel):
    job_id: str
    status: Literal["queued"]
    poll_url: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: Literal["queued", "processing", "complete", "failed"]
    kind: str | None = None
    pages_flagged: int | None = None
    elapsed_seconds: float | None = None
    error: str | None = None
    download_url: str | None = None
    expires_in_seconds: int | None = None


# Note: vector_mode / raster_mode are declared directly as individual Form()
# fields on the /api/v1/documents endpoint in main.py rather than as a single
# Pydantic model here. Multipart/form-data requests (required for file
# upload) can't carry a nested JSON body part, so a model declared without
# Form() gets misparsed by clients (including Swagger UI) that submit it as
# a raw JSON string — see main.py for the working implementation.


# ---- Redaction integrity audit (read-only, distinct feature) ---------------

class RedactionFindingResponse(BaseModel):
    page_number: int
    rect: tuple[float, float, float, float]
    source: str
    risk_level: Literal["critical", "clear", "unknown"]
    underlying_word_count: int
    underlying_char_count: int
    note: str
    revealed_text: str | None = None


class RedactionAuditJobStatusResponse(BaseModel):
    job_id: str
    status: Literal["queued", "processing", "complete", "failed"]
    error: str | None = None
    pages_audited: int | None = None
    total_boxes_found: int | None = None
    critical_count: int | None = None
    clear_count: int | None = None
    summary: str | None = None
    findings: list[RedactionFindingResponse] | None = None


# ---- Revision forensics: discovery is read-only; extraction is gated -------

class RevisionMetadataResponse(BaseModel):
    revision_index: int
    size_bytes: int
    is_current: bool
    page_count: int | None
    object_count: int | None
    creation_date: str | None
    mod_date: str | None
    openable: bool
    note: str


class RevisionDiscoveryJobStatusResponse(BaseModel):
    job_id: str
    status: Literal["queued", "processing", "complete", "failed"]
    error: str | None = None
    total_revisions_found: int | None = None
    pages_in_current_revision: int | None = None
    summary: str | None = None
    truncated: bool | None = None
    revisions: list[RevisionMetadataResponse] | None = None


class RevisionExtractionJobStatusResponse(BaseModel):
    job_id: str
    status: Literal["queued", "processing", "complete", "failed"]
    error: str | None = None
    revision_index: int | None = None
    download_url: str | None = None
    expires_in_seconds: int | None = None
