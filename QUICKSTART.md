# QUICKSTART

Get ClearText running locally in a few minutes. Two paths are covered:

- **[Docker](#option-a-docker-fastest)** — spins up the API, worker, and Redis together. Recommended if you just want it running.
- **[Native / virtualenv](#option-b-native-virtualenv-for-active-development)** — recommended if you're actively editing the pipeline code and want fast reload cycles + a debugger attached.

Both paths assume you're working from the `cleartext/` project root (the directory containing `requirements.txt`, `Dockerfile`, `core/`, `api/`, `worker/`).

---

## Option A: Docker (fastest)

**Prerequisites:** Docker and Docker Compose installed.

```bash
docker compose up --build
```

This starts three services:

- `api` — FastAPI server on `http://localhost:8000`
- `worker` — Celery worker(s) processing documents in the background
- `redis` — broker + result backend

Visit `http://localhost:8000/docs` for interactive API docs. To tear down:

```bash
docker compose down
```

Skip to [Verifying the setup](#verifying-the-setup) once it's up.

---

## Option B: Native / virtualenv (for active development)

### 1. Prerequisites

- **Python 3.11 or 3.12**
- **Redis** running locally (broker + result backend for Celery)
- **System libraries for OpenCV/PyMuPDF** (Linux only — macOS/Windows wheels bundle what they need)

#### Install Redis

```bash
# macOS (Homebrew)
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y redis-server
sudo systemctl start redis-server

# Windows
# Use WSL2 + the Ubuntu instructions above, or run Redis via Docker:
docker run -d -p 6379:6379 redis:7-alpine
```

Confirm Redis is reachable:

```bash
redis-cli ping
# expect: PONG
```

#### Linux system libraries (skip on macOS/Windows)

```bash
sudo apt-get install -y libgl1 libglib2.0-0
```

These satisfy OpenCV's headless runtime dependencies.

### 2. Create and activate a virtual environment

From the `cleartext/` project root:

```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Windows (cmd.exe)
python -m venv .venv
.venv\Scripts\activate.bat
```

Your shell prompt should now be prefixed with `(.venv)`. Confirm you're pointed at the venv's interpreter:

```bash
which python      # macOS/Linux — should print a path inside .venv/
where python       # Windows
```

To leave the environment later: `deactivate`.

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs FastAPI, Uvicorn, Celery, Redis client, PyMuPDF, pikepdf, OpenCV (headless), NumPy, and Pillow.

### 4. Set environment variables

The app works with defaults out of the box, but for local dev you'll typically point Celery at your local Redis and loosen CORS:

```bash
# macOS / Linux
export CT_CELERY_BROKER_URL="redis://localhost:6379/0"
export CT_CELERY_BACKEND_URL="redis://localhost:6379/1"
export CT_ALLOWED_ORIGINS="http://localhost:3000"

# Windows (PowerShell)
$env:CT_CELERY_BROKER_URL="redis://localhost:6379/0"
$env:CT_CELERY_BACKEND_URL="redis://localhost:6379/1"
$env:CT_ALLOWED_ORIGINS="http://localhost:3000"
```

See `core/config.py` for the full list of overridable `CT_*` settings (upload limits, detection thresholds, job TTL, etc).

### 5. Run the Celery worker

In one terminal (with the venv activated):

```bash
export PYTHONPATH=$(pwd)/..   # ensures `cleartext` is importable as a package
celery -A cleartext.worker.celery_app worker --loglevel=info --concurrency=4
```

> **Note on `PYTHONPATH`:** the codebase imports itself as `cleartext.core...` / `cleartext.worker...`, so the *parent* of the `cleartext/` directory needs to be on the path. If your shell is already `cd`'d into the parent directory (one level above `cleartext/`), you can instead just run:
> ```bash
> celery -A cleartext.worker.celery_app worker --loglevel=info --concurrency=4
> ```
> from there. Either approach works — pick whichever matches how you `cd`'d in.

You should see the worker connect to Redis and report itself ready.

### 6. Run the FastAPI dev server

In a second terminal (venv activated, same `PYTHONPATH` consideration as above):

```bash
uvicorn cleartext.api.main:app --reload --host 0.0.0.0 --port 8000
```

`--reload` gives you hot-reload on code changes — ideal for iterating on the detection pipelines.

### 7. Verifying the setup

With both the worker and API running:

```bash
curl http://localhost:8000/healthz
# {"status":"ok"}
```

Open `http://localhost:8000/docs` in a browser for the interactive Swagger UI, or submit a document directly:

```bash
curl -X POST http://localhost:8000/api/v1/documents \
  -F "file=@/path/to/your/document.pdf"
# {"job_id": "...", "status": "queued", "poll_url": "/api/v1/documents/..."}

curl http://localhost:8000/api/v1/documents/<job_id>
# poll until "status": "complete", then...

curl http://localhost:8000/api/v1/documents/<job_id>/download -o cleaned_output.pdf
```

---

## Running the pipeline modules directly (no server needed)

For fast iteration on detection logic without spinning up the API/worker/Redis stack, you can call the core pipelines directly in a Python shell or script:

```python
from cleartext.core.validation import validate_and_sanitize
from cleartext.core.vector_pipeline import clean_pdf
from cleartext.core.raster_pipeline import clean_image

with open("sample.pdf", "rb") as f:
    raw = f.read()

validated = validate_and_sanitize(raw)
cleaned_bytes, flagged_shapes = clean_pdf(validated.sanitized_bytes, mode="mask")

with open("cleaned.pdf", "wb") as f:
    f.write(cleaned_bytes)

print(f"Flagged {len(flagged_shapes)} shape(s) across the document.")
```

This is the fastest loop for tuning detection thresholds in `core/config.py` (`VECTOR_*` / `RASTER_*` settings) — no need to touch Celery or FastAPI at all.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `ModuleNotFoundError: No module named 'cleartext'` | `PYTHONPATH` isn't set to the parent of `cleartext/`, or you're running from the wrong directory. |
| Celery worker can't connect to Redis | Redis isn't running, or `CT_CELERY_BROKER_URL` points at the wrong host/port. Run `redis-cli ping` to confirm. |
| `ImportError` on `cv2` at import time (Linux only) | Missing `libgl1` / `libglib2.0-0` system packages — see step 1. |
| Job stays `"queued"` forever | No worker is running, or the worker process crashed — check the worker terminal's logs. |
| `413` on upload | File exceeds `CT_MAX_UPLOAD_BYTES` (default 50MB). Raise it via the env var if intentional. |
