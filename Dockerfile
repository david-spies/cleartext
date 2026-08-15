FROM python:3.12-slim AS base

# System deps for OpenCV (headless) and PyMuPDF's rendering backend.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/false cleartext
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/cleartext

# No writable app code at runtime; only /tmp (ephemeral workspace) is writable.
RUN chown -R cleartext:cleartext /app && chmod -R go-w /app/cleartext
USER cleartext

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "cleartext.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
