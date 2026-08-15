"""
ClearText — core/revision_forensics.py

Detects and (under an explicit gate) recovers prior revisions hiding inside
a PDF's incremental-save history. This module is split into two halves with
deliberately different trust levels — see the module-level warning at the
bottom before using extract_revision().

BACKGROUND
  A PDF can be updated "incrementally": instead of rewriting the file, an
  editor appends new objects plus a fresh trailer whose /Prev key points
  back at the previous trailer's byte offset, ending in its own
  `startxref <offset>\\n%%EOF` marker. A compliant reader only ever shows
  the LAST such state — but every earlier state is often still sitting in
  the file's raw bytes, fully intact, recoverable by truncating the file
  right after an earlier `%%EOF` marker. This is a real, publicly
  documented technique (it's the mechanism behind several well-known
  incidents of "redacted" government/legal PDFs turning out to still
  contain the original, pre-redaction text when the file was edited
  in-place instead of fully re-exported).

WHY DISCOVERY AND EXTRACTION ARE SEPARATE FUNCTIONS, WITH DIFFERENT DEFAULTS
  discover_revisions() is safe to run on anything, unconditionally, the same
  way redaction_audit.py's default output is safe: it reports structural
  facts (how many prior states exist, their approximate size and page
  count, and any timestamps in each revision's /Info dictionary) without
  materializing or returning a single byte of document content. That's
  enough to answer "does this PDF leak revision history?" — the compliance
  question — without the tool itself becoming a general-purpose mechanism
  for recovering content someone else removed from a document you don't
  own.

  extract_revision() is a different, heavier capability: it reconstructs
  and returns a COMPLETE, standalone historical PDF — potentially an entire
  earlier draft, not just a snippet of text. This is only appropriate when
  the caller is the document's own custodian doing remediation (e.g.
  confirming that an old draft they thought was gone is in fact still
  recoverable, so they can properly flatten/re-export it). It requires an
  explicit `confirm_ownership=True` and is never invoked implicitly by
  discover_revisions(). See its docstring for the full warning — this
  mirrors the reveal_text gate in redaction_audit.py.

WHAT THIS DOES NOT DO
  - Does not touch raster images (PNG/JPEG/TIFF) — incremental saves are a
    PDF container-format feature; there's no equivalent concept for a flat
    raster file.
  - Does not modify the input document in any way.
  - Extraction re-runs the same exploit screening (validation.py) against
    every recovered revision before returning it — an old draft can easily
    contain active content (embedded JS, launch actions) that a LATER save
    stripped out specifically because it was dangerous. Recovering it must
    not resurrect that risk.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from datetime import datetime

import pikepdf

from .config import settings
from .validation import ValidationError, validate_and_sanitize

# Matches a complete, well-formed end-of-revision marker per PDF spec
# §7.5.5: "startxref", the byte offset of that revision's own cross-
# reference section, then "%%EOF". This is a far more precise boundary
# signature than a bare "%%EOF" scan (which produces false positives inside
# compressed stream data far more often) and — critically — every
# occurrence is collected via finditer, not the first/last one picked by a
# single re.search: a naive re.search(...).group(1) approach returns
# whichever match happens to be first in the byte stream, which for a
# multi-revision file is the OLDEST revision's marker, not the current
# one — exactly backwards from what PDF readers are specified to do
# (start from the LAST startxref in the file). Collecting every match and
# reasoning over the full ordered list sidesteps that failure mode entirely.
_REVISION_BOUNDARY_RE = re.compile(rb"startxref\s+(\d+)\s*%%EOF")

_DATE_FIELDS = ("/CreationDate", "/ModDate")


@dataclass(frozen=True)
class RevisionMetadata:
    revision_index: int          # 1 = oldest, N = current/final state
    boundary_end_offset: int     # byte offset in the ORIGINAL upload this revision ends at
    size_bytes: int
    is_current: bool             # True for the revision matching the full uploaded file
    page_count: int | None
    object_count: int | None
    creation_date: str | None    # raw /Info value as stored — not parsed/trusted, informational only
    mod_date: str | None
    openable: bool               # False if even pikepdf(recover=True) couldn't parse it
    note: str = ""


@dataclass
class RevisionDiscoveryReport:
    total_revisions_found: int
    pages_in_current_revision: int | None
    revisions: list[RevisionMetadata] = field(default_factory=list)
    summary: str = ""
    truncated: bool = False  # True if FORENSICS_MAX_BOUNDARY_CANDIDATES was hit


def _find_boundary_candidates(raw: bytes) -> list[int]:
    """Returns end-offsets (exclusive) of every well-formed revision boundary,
    in ascending byte-order (oldest first), capped for DoS resistance."""
    ends = []
    for match in _REVISION_BOUNDARY_RE.finditer(raw):
        ends.append(match.end())
        if len(ends) >= settings.FORENSICS_MAX_BOUNDARY_CANDIDATES:
            break
    # Dedup: identical end-offsets can't occur from finditer on non-overlapping
    # matches, but guard anyway in case of future pattern changes.
    return sorted(set(ends))


def _inspect_slice(raw: bytes, end_offset: int) -> tuple[bool, int | None, int | None, str | None, str | None, str]:
    """
    Attempts to open raw[:end_offset] as a standalone PDF. Returns
    (openable, page_count, object_count, creation_date, mod_date, note).
    Never raises — a slice that doesn't parse is a normal, expected outcome
    (most candidate boundaries from a naive byte-pattern scan are not real
    revision edges, e.g. a coincidental match inside compressed stream data)
    and is reported as such rather than treated as an error.
    """
    candidate = raw[:end_offset]
    if len(candidate) < settings.FORENSICS_MIN_REVISION_BYTES:
        return False, None, None, None, None, "Slice too small to be a real revision — likely a coincidental byte match."

    doc = None
    note = ""
    for recover in (False, True):
        try:
            doc = pikepdf.open(io.BytesIO(candidate), attempt_recovery=recover)
            if recover:
                note = "Opened via recovery mode — trailing structure was imperfect but content was readable."
            break
        except Exception:
            continue

    if doc is None:
        return False, None, None, None, None, "Could not be parsed as a standalone PDF, even in recovery mode."

    try:
        page_count = len(doc.pages)
        object_count = len(doc.objects)
        info = doc.docinfo if doc.trailer.get("/Info") is not None else {}
        creation_date = str(info.get("/CreationDate")) if info and "/CreationDate" in info else None
        mod_date = str(info.get("/ModDate")) if info and "/ModDate" in info else None
        return True, page_count, object_count, creation_date, mod_date, note
    except Exception:
        return True, None, None, None, None, "Opened but metadata could not be fully read."
    finally:
        doc.close()


def discover_revisions(raw_pdf_bytes: bytes) -> RevisionDiscoveryReport:
    """
    Read-only. Never returns document content — only structural facts about
    each discovered revision. Safe to call unconditionally on any PDF.
    """
    boundaries = _find_boundary_candidates(raw_pdf_bytes)
    truncated = len(boundaries) >= settings.FORENSICS_MAX_BOUNDARY_CANDIDATES

    revisions: list[RevisionMetadata] = []
    for idx, end_offset in enumerate(boundaries, start=1):
        openable, page_count, object_count, creation_date, mod_date, note = _inspect_slice(
            raw_pdf_bytes, end_offset
        )
        is_current = end_offset >= len(raw_pdf_bytes) - 1  # allow a trailing newline/whitespace
        revisions.append(RevisionMetadata(
            revision_index=idx,
            boundary_end_offset=end_offset,
            size_bytes=end_offset,
            is_current=is_current,
            page_count=page_count,
            object_count=object_count,
            creation_date=creation_date,
            mod_date=mod_date,
            openable=openable,
            note=note,
        ))
        if len(revisions) >= settings.FORENSICS_MAX_REVISIONS_REPORTED:
            truncated = True
            break

    openable_count = sum(1 for r in revisions if r.openable)
    prior_count = sum(1 for r in revisions if r.openable and not r.is_current)

    current_page_count = next((r.page_count for r in reversed(revisions) if r.is_current and r.openable), None)

    if prior_count > 0:
        summary = (
            f"{prior_count} prior revision(s) found still recoverable from this document's "
            f"incremental-save history, in addition to its current state. If any of those "
            f"revisions predate a redaction or content removal, that earlier content may "
            f"still be extractable from this file."
        )
    elif openable_count <= 1:
        summary = "No prior revisions detected — this document does not appear to carry incremental-save history."
    else:
        summary = (
            f"{openable_count} revision boundary marker(s) found, but none besides the "
            f"current state could be parsed as a standalone recoverable document."
        )

    return RevisionDiscoveryReport(
        total_revisions_found=len(revisions),
        pages_in_current_revision=current_page_count,
        revisions=revisions,
        summary=summary,
        truncated=truncated,
    )


def extract_revision(
    raw_pdf_bytes: bytes,
    revision_index: int,
    confirm_ownership: bool,
) -> bytes:
    """
    Reconstructs and returns the COMPLETE byte content of one historical
    revision. This is a fundamentally different capability from
    discover_revisions() above — it materializes an entire standalone
    document, not just a metadata summary.

    ══════════════════════════════════════════════════════════════════════
    WARNING — read before wiring this into any client-facing flow:

    This function must never be exposed as a casual, one-click, default-on
    action in a UI. It should only ever be reached through a deliberate,
    explicitly-labeled step that requires the caller to affirmatively
    confirm they are the document's own owner/custodian performing their
    own remediation — never as a generic "recover this PDF" button offered
    on arbitrary uploaded files. `confirm_ownership` enforces that this
    call-site made that affirmative choice; it is not, and cannot be, an
    actual authorization check — API layers built on this function should
    log every call (who, when, which document, which revision) for audit
    purposes, since this is the one function in ClearText capable of
    surfacing content its uploader did not put in the file they meant to
    share.
    ══════════════════════════════════════════════════════════════════════

    Raises ValueError if confirm_ownership is not True, or ValidationError
    if the recovered revision itself fails ClearText's exploit screening
    (an old draft can contain active content a later save deliberately
    removed — recovering it must not resurrect that risk).
    """
    if not confirm_ownership:
        raise ValueError(
            "extract_revision() requires confirm_ownership=True — this call must originate "
            "from an explicit, owner-confirmed action, never a default or automatic one."
        )

    boundaries = _find_boundary_candidates(raw_pdf_bytes)
    if revision_index < 1 or revision_index > len(boundaries):
        raise ValueError(f"revision_index {revision_index} is out of range (found {len(boundaries)} revision(s)).")

    end_offset = boundaries[revision_index - 1]
    candidate = raw_pdf_bytes[:end_offset]

    try:
        with pikepdf.open(io.BytesIO(candidate)) as doc:
            rebuilt = io.BytesIO()
            doc.save(rebuilt)
            rebuilt_bytes = rebuilt.getvalue()
    except Exception as exc:
        raise ValueError(f"Revision {revision_index} could not be reconstructed as a valid PDF: {exc}")

    # Never bypass exploit screening just because the content is "historical" —
    # re-run it through the exact same gate every fresh upload goes through.
    validated = validate_and_sanitize(rebuilt_bytes)
    return validated.sanitized_bytes
