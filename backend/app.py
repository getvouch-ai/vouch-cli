"""
GetVouch Web API
POST /api/scan  — download a GitHub repo as ZIP and return security findings
GET  /          — serves index.html
GET  /health    — liveness check
"""
import io
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from getvouch.scanner import scan_directory

# ── App ───────────────────────────────────────────────────────────────
app = FastAPI(title="GetVouch API", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Constants ─────────────────────────────────────────────────────────
_GITHUB_RE = re.compile(
    r'^https://github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?$'
)
DOWNLOAD_TIMEOUT_SECS = 60
MAX_ZIP_BYTES         = 50 * 1024 * 1024   # 50 MB hard cap


class ScanRequest(BaseModel):
    repo_url: str


# ── Routes ────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def index():
    html_path = Path(__file__).parent.parent / "index.html"
    if html_path.exists():
        return FileResponse(html_path, media_type="text/html")
    return JSONResponse({"status": "GetVouch API running. POST /api/scan to scan."})


@app.get("/health")
def health():
    return {"status": "ok", "version": "1.2.0"}


@app.post("/api/scan")
def scan_repo(req: ScanRequest):
    """
    Download a public GitHub repo as a ZIP archive (no git required),
    extract it to a temp directory, scan it, and return findings JSON.

    Body:   { "repo_url": "https://github.com/owner/repo" }
    """
    url = req.repo_url.strip().rstrip("/")

    m = _GITHUB_RE.match(url)
    if not m:
        raise HTTPException(
            status_code=400,
            detail="Only public GitHub URLs are supported "
                   "(https://github.com/owner/repo).",
        )

    owner, repo = m.group(1), m.group(2)

    # GitHub ZIP endpoint — always downloads the default branch
    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
    # Fallback to master if main doesn't exist is handled below

    tmpdir = tempfile.mkdtemp(prefix="getvouch_")
    try:
        zip_data = _download_zip(owner, repo, zip_url, tmpdir)
        _extract_zip(zip_data, tmpdir)

        scan_result = scan_directory(tmpdir)
        scan_result["repo_url"] = f"https://github.com/{owner}/{repo}"
        return JSONResponse(content=scan_result)

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(exc)}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── Helpers ───────────────────────────────────────────────────────────
def _download_zip(owner: str, repo: str, zip_url: str, tmpdir: str) -> bytes:
    """Download repo ZIP from GitHub, falling back main→master→404."""
    branches = ["main", "master"]
    last_err  = None

    for branch in branches:
        url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "GetVouch-Scanner/1.2"},
            )
            with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECS) as resp:
                # Stream-read with size cap
                chunks = []
                total  = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ZIP_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"Repository exceeds the {MAX_ZIP_BYTES // 1024 // 1024} MB size limit.",
                        )
                    chunks.append(chunk)
                return b"".join(chunks)

        except urllib.error.HTTPError as e:
            if e.code == 404:
                last_err = e
                continue   # try next branch
            if e.code == 302:
                # Redirected to login — repo is private
                raise HTTPException(status_code=404, detail="Repository not found or is private.")
            raise HTTPException(status_code=400, detail=f"GitHub returned HTTP {e.code}.")
        except HTTPException:
            raise
        except OSError as e:
            raise HTTPException(status_code=408, detail=f"Download timed out or failed: {str(e)}")

    raise HTTPException(status_code=404, detail="Repository not found or is private.")


def _extract_zip(zip_data: bytes, dest: str) -> None:
    """Extract ZIP bytes into dest, stripping the top-level folder GitHub adds."""
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        members = zf.namelist()
        # GitHub wraps everything in "repo-branch/" — detect and strip it
        prefix = members[0] if members[0].endswith("/") else ""
        for member in members:
            if member == prefix:
                continue   # skip the root dir entry itself
            rel = member[len(prefix):]
            if not rel:
                continue
            target = os.path.join(dest, rel)
            if member.endswith("/"):
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    dst.write(src.read())


# ── Dev entry point ───────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
