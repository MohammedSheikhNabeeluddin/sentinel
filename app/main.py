"""
AICTE Cyber Risk Quantification & Investment Optimization Platform
FastAPI main - integrates Strix + Risk Engine + NVIDIA + Investment + Compliance
"""
import os
import json
import re
import shutil
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, File, UploadFile, Form, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from app.core.risk_engine import risk_engine
from app.core.strix_integration import strix_integration
from app.core.ai_decision import nl_query, generate_recommendations, predictive_insights, get_nvidia_client
from app.core.investment_optimizer import optimize, investment_curve, CONTROL_CATALOG
from app.core.compliance_mapper import map_findings_to_framework, generate_evidence_report
from app.core.rag import rag_store, rag_query
from app.core.rag_attack import inject_poison, evaluate_rag_attack, clear_poison, detect_poison_retrieved, guard_with_nemoguard
from app.core.sentinel_adapter import backend_to_frontend_findings, make_project, count_loc, detect_language

app = FastAPI(title="AICTE Cyber Risk + Sentinel", version="1.0.0")

# Mount static
static_dir = Path(__file__).parent.parent / "static"
templates_dir = Path(__file__).parent.parent / "templates"
frontend_dist = Path(__file__).parent.parent / "frontend_dist"
static_dir.mkdir(exist_ok=True)
templates_dir.mkdir(exist_ok=True)
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
# New Sentinel frontend assets (D:\\hackathon\\index.html build)
if (frontend_dist / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="frontend-assets")
templates = Jinja2Templates(directory=str(templates_dir))

# Global state for last scan findings - no hardcoded demo project.
# Project/findings stay empty until a real codebase scan completes.
LAST_FINDINGS: List[dict] = []
LAST_UPLOAD_ID: Optional[str] = None
LAST_PROJECT: Dict = {"name": "no-project", "branch": "main", "commit": "0000000",
                      "language": "Python", "loc": 0, "services": 0, "packages": 0, "source": "none"}
LAST_FRONTEND_FINDINGS: List[dict] = []

# No hardcoded seeding - dashboard shows empty until user uploads & scans real codebase
# Real results only after POST /api/upload + /api/scan or /api/upload-folder
def _seed_initial():
    # intentionally no mock seeding; keep risk_engine empty
    pass

_seed_initial()

@app.get("/legacy", response_class=HTMLResponse)
async def dashboard_legacy(request: Request):
    risk = risk_engine.compute_risk()
    recs = generate_recommendations(risk, LAST_FINDINGS)
    insights = predictive_insights(risk["history"])
    opt = optimize(10000000)  # 1 Cr
    curve = investment_curve()
    nvidia_client, model, key, endpoint = get_nvidia_client()
    nvidia_status = "connected" if key else "missing_key - add NVIDIA_API_KEY to .env"
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "risk": risk,
        "findings": LAST_FINDINGS,
        "recs": recs,
        "insights": insights,
        "opt": opt,
        "curve": curve,
        "catalog": CONTROL_CATALOG,
        "nvidia_model": model,
        "nvidia_endpoint": endpoint,
        "nvidia_status": nvidia_status,
        "upload_id": LAST_UPLOAD_ID,
        "rag_docs_count": len(rag_store.metas)
    })

def _serve_new_frontend():
    idx = frontend_dist / "index.html"
    if idx.exists():
        return FileResponse(str(idx), media_type="text/html")
    return HTMLResponse("<h1>Frontend not found. Run from D:\\hackathon\\cyber-risk-platform</h1>", status_code=404)

@app.get("/", response_class=HTMLResponse)
async def new_frontend_root():
    return _serve_new_frontend()

@app.get("/risk", response_class=HTMLResponse)
async def new_frontend_risk():
    return _serve_new_frontend()

@app.get("/findings", response_class=HTMLResponse)
async def new_frontend_findings():
    return _serve_new_frontend()

@app.get("/plan", response_class=HTMLResponse)
async def new_frontend_plan():
    return _serve_new_frontend()

@app.get("/sentinel-bridge.js")
async def sentinel_bridge():
    fp = frontend_dist / "sentinel-bridge.js"
    if fp.exists():
        return FileResponse(str(fp), media_type="application/javascript")
    return HTMLResponse("// bridge missing", status_code=404)

@app.get("/favicon.png")
async def favicon():
    # avoid 404 noise; return empty
    return HTMLResponse("", status_code=204)

@app.get("/api/health")
async def health():
    c, m, k, e = get_nvidia_client()
    return {"status":"ok","strix_path":str(strix_integration.strix_path),"upload_dir":str(strix_integration.upload_dir),"nvidia":{"endpoint":e,"model":m,"has_key":bool(k)},"risk":{"vulns":len(risk_engine.vulns),"assets":len(risk_engine.assets)}}

@app.post("/api/upload")
async def upload_codebase(file: UploadFile = File(...)):
    # Single zip/tar file upload
    tmp_path = Path(strix_integration.upload_dir) / f"tmp_{file.filename}"
    with open(tmp_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    info = strix_integration.handle_upload(tmp_path, file.filename)
    try:
        tmp_path.unlink()
    except: pass
    global LAST_UPLOAD_ID
    LAST_UPLOAD_ID = info["upload_id"]
    return {"message":"uploaded & extracted","info":info}

@app.post("/api/upload-folder")
async def upload_folder(files: List[UploadFile] = File(...)):
    """Folder upload via webkitdirectory - receives all files with relative paths"""
    upload_id = str(uuid.uuid4())[:8]
    extract_dir = Path(strix_integration.upload_dir) / upload_id
    extract_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for uf in files:
        # uf.filename contains relative path like "myapp/app.py"
        # sanitize: prevent traversal
        rel = Path(uf.filename)
        # strip leading folder if browser sends absolute?
        # Keep as is but remove drive/root
        parts = [p for p in rel.parts if p not in ("/", "\\", "..")]
        dest = extract_dir.joinpath(*parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as out:
            shutil.copyfileobj(uf.file, out)
        count += 1
    # If no files, error
    if count == 0:
        return {"error":"no files received"}
    file_count = sum(1 for _ in extract_dir.rglob("*") if _.is_file())
    info = {
        "upload_id": upload_id,
        "extracted_path": str(extract_dir.resolve()),
        "original_name": f"folder ({count} files)",
        "file_count": file_count,
    }
    global LAST_UPLOAD_ID
    LAST_UPLOAD_ID = upload_id
    return {"message":"folder uploaded","info":info}

@app.post("/api/scan/{upload_id}")
async def scan_upload(upload_id: str):
    result = strix_integration.scan(upload_id)
    global LAST_FINDINGS, LAST_PROJECT
    if "findings" in result:
        LAST_FINDINGS = result["findings"]
        # Ingest into risk engine - clear previous vulns for fresh view
        risk_engine.vulns = []
        risk_engine.ingest_vulns([{
            "title": f.get("title",""),
            "severity": f.get("severity","medium"),
            "cvss": f.get("cvss") or f.get("cvss_score",5.0),
            "asset_id": f.get("asset_id","web-01"),
            "category": f.get("category","general"),
            "exploitability": f.get("exploitability",0.6)
        } for f in LAST_FINDINGS])
        try:
            target = Path(strix_integration.upload_dir) / upload_id
            LAST_PROJECT = make_project(LAST_PROJECT.get("name", "uploaded/project"), source="upload",
                                        loc=count_loc(target), language=detect_language(target))
        except Exception:
            pass
        _refresh_frontend_findings()
    return result

@app.get("/api/risk/summary")
async def risk_summary():
    risk = risk_engine.compute_risk()
    return risk

@app.get("/api/findings")
async def get_findings():
    return {"count": len(LAST_FINDINGS), "findings": LAST_FINDINGS}

# --- New Sentinel frontend (D:\\hackathon\\index.html) wiring ---
def _refresh_frontend_findings():
    """Rebuild LAST_FRONTEND_FINDINGS from LAST_FINDINGS + risk_engine EAL."""
    global LAST_FRONTEND_FINDINGS
    # Build per-finding EAL map from risk engine if available
    risk = risk_engine.compute_risk()
    # risk per asset -> distribute proportionally is complex; use EAL total split by severity
    # Simpler: let adapter estimate, then scale so sum(exposureInr) ~= total EAL
    fe = backend_to_frontend_findings(LAST_FINDINGS)
    try:
        total_eal = risk["org"]["total_eal_inr"]
        s = sum(f["exposureInr"] for f in fe)
        if s > 0 and total_eal > 0:
            factor = total_eal / s
            # clamp factor to avoid absurd values from mock scaling
            factor = max(0.3, min(3.0, factor))
            for f in fe:
                f["exposureInr"] = int(f["exposureInr"] * factor)
                # rebuild breakdown proportionally
                tot = f["exposureInr"]
                parts = [0.38, 0.28, 0.16, 0.12, 0.06]
                labels = ["Customer data stolen", "Government fine (DPDP Act)", "Cleaning up the hack",
                          "App down, business stops", "Rebuilding and testing"]
                bd = []
                acc = 0
                for i, (lab, p) in enumerate(zip(labels, parts)):
                    v = int(round(tot * p / 1000.0) * 1000)
                    if i == len(labels) - 1:
                        v = int(tot - acc)
                    acc += v
                    bd.append({"label": lab, "value": v})
                f["breakdown"] = bd
            fe.sort(key=lambda x: x["exposureInr"], reverse=True)
            for i, f in enumerate(fe):
                f["id"] = f"SEN-{str(i+1).zfill(3)}"
    except Exception:
        pass
    LAST_FRONTEND_FINDINGS = fe
    return fe

@app.get("/api/sentinel/latest")
async def sentinel_latest():
    """Returns {project, findings} in new-UI shape. Empty findings until real scan."""
    fe = _refresh_frontend_findings() if LAST_FINDINGS else []
    return {"project": LAST_PROJECT, "findings": fe, "upload_id": LAST_UPLOAD_ID,
            "count": len(fe), "has_data": len(fe) > 0}

@app.get("/api/sentinel/project")
async def sentinel_project():
    return {"project": LAST_PROJECT, "upload_id": LAST_UPLOAD_ID}

class SentinelGitReq(BaseModel):
    repo_url: str
    access_token: Optional[str] = None

@app.post("/api/sentinel/scan-git")
async def sentinel_scan_git(req: SentinelGitReq):
    """GitHub link flow (practice-copy pentest, live app never touched):
    1. Validate public github.com URL (or token-injected private URL).
    2. `git clone --depth 1 <url> uploads/<id>/repo` - this is how the app gets repo access (no GitHub OAuth, just git).
    3. Scan the CLONED copy only: try real Strix (`strix -n --target`, needs Docker+NVIDIA key) else fallback static patterns.
    4. Ingest into risk_engine, map to Sentinel SEN-xxx shape with money values.
    Private repos need access_token (sent as https://x-access-token:<token>@github.com/...), never stored.
    """
    import subprocess
    global LAST_FINDINGS, LAST_UPLOAD_ID, LAST_PROJECT
    repo_url = (req.repo_url or "").strip()
    token = (req.access_token or "").strip()
    # accept owner/repo shorthand too
    if re.match(r"^[^/\s]+/[^/\s]+$", repo_url) and "://" not in repo_url:
        repo_url = "https://github.com/" + repo_url
    # the old demo's fictional project never existed on GitHub - say so plainly
    if "acme-corp" in repo_url.lower():
        return {"error": "acme-corp/payments-api is a fictional demo name, not a real repository. Paste a real link (e.g. https://github.com/octocat/Hello-World), your own repo, or use Upload ZIP / Upload Folder."}
    # basic validation - only github http(s) allowed
    if not re.match(r"^https?://(www\.)?github\.com/[^/]+/[^/]+", repo_url):
        return {"error": "Only public https://github.com/<owner>/<repo> links supported. Example: https://github.com/org/repo. Or type owner/repo shorthand, or use Upload ZIP / Upload Folder."}
    # derive name like acme-corp/payments-api
    name = re.sub(r"^https?://(www\.)?github\.com/", "", repo_url).strip().rstrip("/").removesuffix(".git")
    if not name or "/" not in name:
        name = repo_url.replace("https://", "").replace("http://", "")[:60] or "uploaded/project"
    # inject token for private repos without logging it
    clone_url = repo_url
    if token:
        clone_url = re.sub(r"^https://", f"https://x-access-token:{token}@", repo_url)
    upload_id = str(uuid.uuid4())[:8]
    dest = Path(strix_integration.upload_dir) / upload_id
    dest.mkdir(parents=True, exist_ok=True)
    try:
        # shallow clone into locked practice copy; live repo never touched
        r = subprocess.run(["git", "clone", "--depth", "1", clone_url, str(dest / "repo")],
                           capture_output=True, timeout=120, text=True)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "")[:500]
            # scrub token from error
            if token:
                err = err.replace(token, "***")
            hint = "If private, paste a fine-grained PAT (Contents:read) in the token field. Public repos need no token."
            return {"error": f"git clone failed: {err}. {hint}", "upload_id": upload_id}
        target = dest / "repo"
        loc = count_loc(target)
        lang = detect_language(target)
        # move repo contents up one level for scanner simplicity? keep as is, scan target
        # scan via strix_integration.scan expects uploads/<id>; create symlink-like by scanning subdir manually
        from app.core.sentinel_adapter import backend_to_frontend_findings as _b2f
        # reuse scan logic on subdir
        findings = strix_integration.fallback_static_scan(target)
        real = strix_integration.try_real_strix(target)
        source = "strix" if real is not None else (findings[0].get("source", "fallback_static") if findings else "mock")
        if real is not None:
            findings = real
        # save report
        report_path = strix_integration.runs_dir / f"{upload_id}.json"
        report_path.write_text(json.dumps({"upload_id": upload_id, "source": source, "findings": findings}, indent=2))
        result = {"upload_id": upload_id, "source": source, "findings": findings, "count": len(findings)}
        LAST_FINDINGS = findings
        risk_engine.vulns = []
        risk_engine.ingest_vulns([{"title": f.get("title", ""), "severity": f.get("severity", "medium"),
                                   "cvss": f.get("cvss") or f.get("cvss_score", 5.0),
                                   "asset_id": f.get("asset_id", "web-01"),
                                   "category": f.get("category", "general"),
                                   "exploitability": f.get("exploitability", 0.6)} for f in findings])
        LAST_UPLOAD_ID = upload_id
        LAST_PROJECT = make_project(name, source="git", loc=loc, language=lang)
        fe = _refresh_frontend_findings()
        return {"project": LAST_PROJECT, "findings": fe, "count": len(fe), "upload_id": upload_id, "source": source}
    except Exception as e:
        return {"error": str(e)[:500], "upload_id": upload_id}

@app.post("/api/sentinel/upload")
async def sentinel_upload(file: UploadFile = File(...)):
    """ZIP upload wired for new UI: extract, scan, return new-UI shape."""
    global LAST_FINDINGS, LAST_UPLOAD_ID, LAST_PROJECT
    tmp_path = Path(strix_integration.upload_dir) / f"tmp_{file.filename}"
    with open(tmp_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    info = strix_integration.handle_upload(tmp_path, file.filename)
    try:
        tmp_path.unlink()
    except:
        pass
    upload_id = info["upload_id"]
    result = strix_integration.scan(upload_id)
    findings = result.get("findings", [])
    LAST_FINDINGS = findings
    risk_engine.vulns = []
    risk_engine.ingest_vulns([{"title": f.get("title", ""), "severity": f.get("severity", "medium"),
                               "cvss": f.get("cvss") or f.get("cvss_score", 5.0),
                               "asset_id": f.get("asset_id", "web-01"),
                               "category": f.get("category", "general"),
                               "exploitability": f.get("exploitability", 0.6)} for f in findings])
    LAST_UPLOAD_ID = upload_id
    target = Path(strix_integration.upload_dir) / upload_id
    proj_name = Path(file.filename).stem.replace("_", "-").replace(" ", "-")[:60] or "uploaded/project"
    LAST_PROJECT = make_project(proj_name, source="upload", loc=count_loc(target), language=detect_language(target))
    fe = _refresh_frontend_findings()
    return {"project": LAST_PROJECT, "findings": fe, "count": len(fe),
            "upload_id": upload_id, "source": result.get("source"), "file_count": info.get("file_count")}

@app.post("/api/sentinel/upload-folder")
async def sentinel_upload_folder(files: List[UploadFile] = File(...)):
    """Non-zip codebase folder upload (webkitdirectory) wired for new UI: save tree, scan, return new-UI shape."""
    global LAST_FINDINGS, LAST_UPLOAD_ID, LAST_PROJECT
    upload_id = str(uuid.uuid4())[:8]
    extract_dir = Path(strix_integration.upload_dir) / upload_id
    extract_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    top_folder = ""
    for uf in files:
        rel = Path(uf.filename or f"file-{count}")
        parts = [p for p in rel.parts if p not in ("/", "\\", "..")]
        if not parts:
            continue
        if not top_folder:
            top_folder = parts[0] if len(parts) > 1 else "uploaded-project"
        dest = extract_dir.joinpath(*parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as out:
            shutil.copyfileobj(uf.file, out)
        count += 1
    if count == 0:
        return {"error": "no files received - select a folder, not a single file"}
    result = strix_integration.scan(upload_id)
    findings = result.get("findings", [])
    LAST_FINDINGS = findings
    risk_engine.vulns = []
    risk_engine.ingest_vulns([{"title": f.get("title", ""), "severity": f.get("severity", "medium"),
                               "cvss": f.get("cvss") or f.get("cvss_score", 5.0),
                               "asset_id": f.get("asset_id", "web-01"),
                               "category": f.get("category", "general"),
                               "exploitability": f.get("exploitability", 0.6)} for f in findings])
    LAST_UPLOAD_ID = upload_id
    proj_name = (top_folder.replace("_", "-").replace(" ", "-")[:60] or "uploaded-project")
    LAST_PROJECT = make_project(proj_name, source="upload", loc=count_loc(extract_dir), language=detect_language(extract_dir))
    fe = _refresh_frontend_findings()
    return {"project": LAST_PROJECT, "findings": fe, "count": len(fe),
            "upload_id": upload_id, "source": result.get("source"), "file_count": count}

class QueryReq(BaseModel):
    question: str

@app.post("/api/query")
async def query_nl(req: QueryReq):
    risk = risk_engine.compute_risk()
    ans = nl_query(req.question, risk)
    return ans

class SimulateReq(BaseModel):
    mfa_all_privileged: bool = False
    patch_high: bool = False
    network_segmentation: bool = False
    additional_monitoring: bool = False
    delay_days: int = 0
    cost_inr: int = 1500000

@app.post("/api/simulate")
async def simulate(req: SimulateReq):
    result = risk_engine.simulate(req.model_dump())
    return result

@app.get("/api/investment/optimize")
async def investment_optimize(budget: int = 10000000):
    # budget in INR, e.g., 10000000 = 1 Cr
    result = optimize(budget)
    return result

@app.get("/api/investment/curve")
async def curve():
    return {"points": investment_curve()}

@app.get("/api/compliance/report")
async def compliance_report():
    risk = risk_engine.compute_risk()
    report = generate_evidence_report(LAST_FINDINGS, risk)
    return report

@app.get("/api/compliance/{framework}")
async def compliance_one(framework: str):
    # framework keys: ISO27001, NIST, CIS, RBI, SEBI
    fk = framework.upper()
    # normalize ISO27001 variations
    if fk in ["ISO","ISO27001","ISO/IEC27001"]:
        fk = "ISO27001"
    result = map_findings_to_framework(LAST_FINDINGS, fk)
    return result

@app.get("/api/recommendations")
async def recommendations():
    risk = risk_engine.compute_risk()
    recs = generate_recommendations(risk, LAST_FINDINGS)
    return {"recommendations": recs}

@app.post("/api/clear")
async def clear_data():
    global LAST_FINDINGS, LAST_UPLOAD_ID, LAST_FRONTEND_FINDINGS, LAST_PROJECT
    risk_engine.vulns = []
    risk_engine.history = []
    LAST_FINDINGS = []
    LAST_UPLOAD_ID = None
    LAST_FRONTEND_FINDINGS = []
    LAST_PROJECT = {"name": "no-project", "branch": "main", "commit": "0000000",
                    "language": "Python", "loc": 0, "services": 0, "packages": 0, "source": "none"}
    # also clear uploads folder contents metadata? keep files but clear risk
    return {"cleared": True, "message":"All risk data cleared - upload & scan to see real results"}

# --- RAG + RAG Attack ---
class RagQueryReq(BaseModel):
    question: str

@app.post("/api/rag/query")
async def rag_query_endpoint(req: RagQueryReq):
    risk = risk_engine.compute_risk()
    result = rag_query(req.question, risk)
    return result

@app.post("/api/attack/rag-poison")
async def attack_rag_poison(question: str = "What is our EAL and compliance?"):
    result = evaluate_rag_attack(question, with_guard=True)
    return result

@app.post("/api/attack/inject-poison")
async def inject_poison_endpoint(poison_id: str = "poison-001"):
    doc = inject_poison(poison_id)
    return {"injected": doc, "total_docs": len(rag_store.metas)}

@app.post("/api/attack/clear-poison")
async def clear_poison_endpoint():
    res = clear_poison()
    return res

@app.get("/api/rag/docs")
async def list_rag_docs():
    return {"count": len(rag_store.metas), "docs": rag_store.metas[:20]}

@app.post("/api/ingest/mock")
async def ingest_mock():
    """Inject additional mock data from SIEM/IAM/EDR/CSPM sources for demo"""
    extra = [
        {"title":"EDR: Mimikatz detected on IAM host","severity":"critical","cvss":9.0,"asset_id":"iam-01","category":"rce","exploitability":0.9},
        {"title":"CSPM: S3 bucket public read","severity":"high","cvss":7.8,"asset_id":"edr-01","category":"exposure","exploitability":0.65},
        {"title":"SIEM: Brute force on portal","severity":"medium","cvss":6.0,"asset_id":"web-01","category":"idor","exploitability":0.5},
    ]
    risk_engine.ingest_vulns(extra)
    global LAST_FINDINGS
    LAST_FINDINGS.extend([{"id":f"SIEM-{i}",**e,"cvss_score":e["cvss"],"source":"siem"} for i,e in enumerate(extra)])
    return {"ingested": len(extra), "total_vulns": len(risk_engine.vulns)}

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("APP_HOST","127.0.0.1")
    port = int(os.getenv("APP_PORT","8000"))
    print(f"Starting AICTE Cyber Risk + Sentinel at http://{host}:{port}")
    print(f"Upload dir: {strix_integration.upload_dir.resolve()}")
    print(f"NVIDIA endpoint: {os.getenv('NVIDIA_ENDPOINT')} model: {os.getenv('NVIDIA_MODEL')} key_set: {bool(os.getenv('NVIDIA_API_KEY'))}")
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
    # i am contributor 
