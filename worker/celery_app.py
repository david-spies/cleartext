"""
ClearText — worker/celery_app.py

Celery config for concurrent multi-document / multi-page processing.
Redis is used as both broker and result backend for simplicity; swap for
SQS/RabbitMQ + a dedicated result store at higher scale.

Hardening notes:
  - `task_time_limit` gives every job a hard wall-clock kill switch, so a
    pathological input that slips past validation (e.g. a CV operation that
    pathologically degrades on crafted pixel data) can't hang a worker
    indefinitely.
  - `worker_max_tasks_per_child` recycles worker processes periodically to
    bound the blast radius of any memory leak or partial-corruption state
    left behind by a malformed-file edge case.
  - Results carry no payload persistence beyond `result_expires` — this is
    the queue-level half of the zero-retention guarantee.
"""
from __future__ import annotations

import os

from celery import Celery

from cleartext.core.config import settings

BROKER_URL = os.environ.get("CT_CELERY_BROKER_URL", "redis://localhost:6379/0")
BACKEND_URL = os.environ.get("CT_CELERY_BACKEND_URL", "redis://localhost:6379/1")

celery_app = Celery("cleartext", broker=BROKER_URL, backend=BACKEND_URL)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_time_limit=settings.PROCESSING_TIMEOUT_SECONDS + 15,
    task_soft_time_limit=settings.PROCESSING_TIMEOUT_SECONDS,
    worker_max_tasks_per_child=200,
    worker_prefetch_multiplier=1,  # fairness for large-doc jobs over throughput
    result_expires=settings.JOB_TTL_SECONDS,  # zero-retention: auto-purge results
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

celery_app.autodiscover_tasks(["cleartext.worker"])
