"""
GetVouch Web API
POST /api/scan  — clone a GitHub repo and return security findings as JSON
GET  /          — landing page (index.html served as static file)
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from getvouch.scanner import scan_directory

# ── App ──────────────────────────────────────────────────────────────
app = FastAPI(title="GetVouch API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Validation ───────────────────────────────────────────────────────
# Allow: https://github.com/owner/repo  or  https://github.com/owner/repo.git
_GITHUB_RE = re.compile(
    r'^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(\.git)?$'
)

CLONE_TIMEOUT_SECS = 90   # hard limit for git clone
MAX_REPO_NAME_LEN  = 200


class ScanRequest(BaseModel):
    repo_url: str


# ── Routes ───────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def index():
    """Serve the landing page."""
    html_path = Path(__file__).parent / "index.html"
    if html_path.exists():
        return FileResponse(html_path, media_type="text/html")
    return JSONResponse({"status": "GetVouch API is running. POST /api/scan to scan a repo."})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def scan_repo(req: ScanRequest):
    """
    Clone a public GitHub repo and return security findings.

    Body:  { "repo_url": "https://github.com/owner/repo" }
    Returns the scan result JSON from scan_directory().
    """
    url = req.repo_url.strip().rstrip("/")

    # Normalise: strip trailing .git for validation, add back for clone
    bare_url   = url[:-4] if url.endswith(".git") else url
    clone_url  = bare_url + ".git"

    if not _GITHUB_RE.match(bare_url):
        raise HTTPException(
            status_code=400,
            detail="Only public GitHub URLs are supported (https://github.com/owner/repo)."
        )

    if len(url) > MAX_REPO_NAME_LEN:
        raise HTTPException(status_code=400, detail="URL too long.")

    tmpdir = tempfile.mkdtemp(prefix="getvouch_")
    try:
        result = subprocess.run(
            [
                "git", "clone",
                "--depth", "1",      # shallow clone — only latest snapshot
                "--single-branch",
                "--quiet",
                clone_url,
                tmpdir,
            ],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECS,
        )

        if result.returncode != 0:
            err = result.stderr.strip() or "unknown error"
            if "Repository not found" in err or "not found" in err.lower():
                raise HTTPException(
                    status_code=404,
                    detail="Repository not found or is private."
                )
            raise HTTPException(
                status_code=400,
                detail=f"Failed to clone repository: {err}"
            )

        scan_result = scan_directory(tmpdir)
        scan_result["repo_url"] = bare_url
        return JSONResponse(content=scan_result)

    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail=f"Repository clone timed out after {CLONE_TIMEOUT_SECS}s. "
                   "Try a smaller repository."
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="git is not available on this server. Contact support."
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(exc)}"
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── Dev entry point ──────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
