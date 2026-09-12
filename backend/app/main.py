import asyncio
import datetime
import os

import httpx
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .database import init_db, get_db, SessionLocal
from .models import Target, Scan, Finding
from .schemas import TargetCreate, TargetOut, ScanCreate, ScanOut, FindingOut, DiscoverRequest
from .scanners import MODULE_REGISTRY
from .scanners.crawler import discover as crawl_discover

MANUAL_ONLY_CATEGORIES = [
    {
        "category": "A04:2021-Insecure Design",
        "note": "Requires threat-modeling and business-logic review; not automatable via black-box scanning.",
    },
    {
        "category": "A08:2021-Software and Data Integrity Failures",
        "note": "Review CI/CD pipeline integrity, unsigned updates, and deserialization of untrusted sources manually.",
    },
    {
        "category": "A09:2021-Security Logging and Monitoring Failures",
        "note": "Requires access to server-side logging configuration; verify manually with the target/program.",
    },
]

app = FastAPI(title="BBHT Web")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    os.makedirs(os.path.dirname(os.environ.get("DB_PATH", "./bbht.db")) or ".", exist_ok=True)
    await init_db()


@app.get("/api/manual-checklist")
async def manual_checklist():
    return MANUAL_ONLY_CATEGORIES


@app.post("/api/targets", response_model=TargetOut)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)):
    target = Target(**payload.model_dump())
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@app.get("/api/targets", response_model=list[TargetOut])
async def list_targets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return result.scalars().all()


@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: int, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    await db.delete(target)
    await db.commit()
    return {"ok": True}


async def _execute_scan(scan_id: int, modules: list[str]):
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        scan.status = "running"
        await db.commit()

        findings_buffer: list[dict] = []

        def emit(finding: dict):
            findings_buffer.append(finding)

        async with httpx.AsyncClient(
            headers={"User-Agent": "BBHT-Scanner/1.0 (authorized-testing)"},
            verify=True,
        ) as client:
            for mod_name in modules:
                fn = MODULE_REGISTRY.get(mod_name)
                if not fn:
                    continue
                scan.progress = f"running: {mod_name}"
                await db.commit()
                try:
                    await asyncio.wait_for(fn(scan.url, client, emit), timeout=180)
                except asyncio.TimeoutError:
                    emit({
                        "category": "Scanner",
                        "title": f"Module '{mod_name}' timed out",
                        "severity": "info",
                        "confidence": "info",
                        "location": scan.url,
                        "evidence": "Module exceeded time budget and was skipped.",
                        "poc": "",
                        "remediation": "",
                    })
                except Exception as e:
                    emit({
                        "category": "Scanner",
                        "title": f"Module '{mod_name}' errored",
                        "severity": "info",
                        "confidence": "info",
                        "location": scan.url,
                        "evidence": str(e)[:300],
                        "poc": "",
                        "remediation": "",
                    })

                for f in findings_buffer:
                    db.add(Finding(scan_id=scan.id, **f))
                findings_buffer.clear()
                await db.commit()

        scan.status = "completed"
        scan.progress = "done"
        scan.finished_at = datetime.datetime.utcnow()
        await db.commit()


@app.post("/api/scans", response_model=ScanOut)
async def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    if not target.authorized:
        raise HTTPException(403, "Target is not marked as authorized for testing")

    unknown = [m for m in payload.modules if m not in MODULE_REGISTRY]
    if unknown:
        raise HTTPException(400, f"Unknown modules: {unknown}")

    scan = Scan(
        target_id=target.id,
        url=payload.url,
        modules=",".join(payload.modules),
        status="queued",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(_execute_scan, scan.id, payload.modules)
    return scan


@app.get("/api/scans", response_model=list[ScanOut])
async def list_scans(target_id: int | None = None, db: AsyncSession = Depends(get_db)):
    stmt = select(Scan).order_by(Scan.started_at.desc())
    if target_id is not None:
        stmt = stmt.where(Scan.target_id == target_id)
    result = await db.execute(stmt)
    return result.scalars().all()


@app.get("/api/scans/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.get("/api/scans/{scan_id}/findings", response_model=list[FindingOut])
async def get_findings(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at.asc())
    )
    return result.scalars().all()


@app.get("/api/modules")
async def list_modules():
    return sorted(MODULE_REGISTRY.keys())


@app.post("/api/discover")
async def discover_endpoint(payload: DiscoverRequest, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    if not target.authorized:
        raise HTTPException(403, "Target is not marked as authorized for testing")

    async with httpx.AsyncClient(
        headers={"User-Agent": "BBHT-Scanner/1.0 (authorized-testing)"},
        verify=True,
    ) as client:
        try:
            result = await asyncio.wait_for(crawl_discover(payload.base_url, client), timeout=60)
        except asyncio.TimeoutError:
            raise HTTPException(504, "Crawl timed out")
    return result


# --- Static frontend (mobile-first PWA) ---
# In Docker the frontend is copied to backend/static; for local dev (running
# straight out of the repo) fall back to the sibling ../frontend directory.
_backend_root = os.path.dirname(os.path.dirname(__file__))
_docker_static = os.path.join(_backend_root, "static")
_dev_static = os.path.join(os.path.dirname(_backend_root), "frontend")
STATIC_DIR = _docker_static if os.path.isdir(_docker_static) else _dev_static
if os.path.isdir(STATIC_DIR):
    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    @app.get("/manifest.json")
    async def manifest():
        return FileResponse(os.path.join(STATIC_DIR, "manifest.json"))

    @app.get("/sw.js")
    async def sw():
        return FileResponse(os.path.join(STATIC_DIR, "sw.js"))
