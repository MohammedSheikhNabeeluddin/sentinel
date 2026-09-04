"""
Strix Integration
- Handles codebase upload (zip/tar), extraction, and scan
- Tries real strix CLI `strix -n --target <path>` if docker + LLM key available
- Falls back to static analysis mock (grep for vuln patterns) + enriched mock findings
- Normalizes findings to RiskEngine Vulnerability format
"""
import os
import re
import json
import zipfile
import tarfile
import shutil
import subprocess
import uuid
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# Patterns for fallback static analysis
VULN_PATTERNS = {
    "SQL Injection": [r"execute\s*\(.*%s", r"cursor\.execute.*\+", r"SELECT.*FROM.*WHERE.*=", r"Statement\.executeQuery"],
    "XSS": [r"innerHTML\s*=", r"document\.write", r"dangerouslySetInnerHTML", r"<script>"],
    "Hardcoded Secret": [r"api_key\s*=\s*['\"][a-zA-Z0-9_\-]{20,}", r"password\s*=\s*['\"].+['\"]", r"AWS_SECRET"],
    "IDOR": [r"user_id\s*=\s*request", r"\/api\/.*\/\{id\}", r"findById\(.*request"],
    "RCE": [r"eval\s*\(", r"exec\s*\(", r"subprocess\.call", r"os\.system"],
    "SSRF": [r"requests\.get\(.*request", r"urllib\.request\.urlopen", r"fetch\(.*user"],
    "XXE": [r"xml\.etree", r"DocumentBuilder", r"<!ENTITY"],
    "Insecure Deserialization": [r"pickle\.loads", r"yaml\.load\(", r"ObjectInputStream"],
}

SEVERITY_MAP = {
    "SQL Injection": "critical",
    "RCE": "critical",
    "Insecure Deserialization": "critical",
    "SSRF": "high",
    "IDOR": "high",
    "XSS": "high",
    "XXE": "high",
    "Hardcoded Secret": "medium",
}

class StrixIntegration:
    def __init__(self, strix_path: str = "D:/hackathon/strix", upload_dir: str = "./uploads"):
        self.strix_path = Path(strix_path)
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir = Path("strix_runs")
        self.runs_dir.mkdir(exist_ok=True)

    def handle_upload(self, file_path: Path, original_name: str) -> Dict[str, Any]:
        """Extract uploaded archive to unique dir, return upload_id and extracted path"""
        upload_id = str(uuid.uuid4())[:8]
        extract_dir = self.upload_dir / upload_id
        extract_dir.mkdir(parents=True, exist_ok=True)
        # Determine type by suffix
        suffix = Path(original_name).suffix.lower()
        try:
            if suffix == ".zip":
                with zipfile.ZipFile(file_path, 'r') as z:
                    z.extractall(extract_dir)
            elif suffix in [".tar", ".gz", ".tgz"]:
                with tarfile.open(file_path, 'r:*') as t:
                    t.extractall(extract_dir)
            else:
                # Single file
                shutil.copy(file_path, extract_dir / original_name)
                # try to treat as zip if fails
        except Exception as e:
            # If extraction fails, copy as is
            shutil.copy(file_path, extract_dir / original_name)

        # Count files
        file_count = sum(1 for _ in extract_dir.rglob("*") if _.is_file())
        return {
            "upload_id": upload_id,
            "extracted_path": str(extract_dir.resolve()),
            "original_name": original_name,
            "file_count": file_count,
        }

    def fallback_static_scan(self, target_path: Path) -> List[Dict]:
        findings = []
        vuln_id = 1000
        for file in target_path.rglob("*"):
            if file.is_file() and file.suffix.lower() in [".py",".js",".java",".ts",".jsx",".php",".go",".rb",".cs",".html",".yaml",".yml",".json",".xml"]:
                try:
                    text = file.read_text(encoding="utf-8", errors="ignore")
                except:
                    continue
                for vuln_name, patterns in VULN_PATTERNS.items():
                    for pat in patterns:
                        if re.search(pat, text, re.IGNORECASE):
                            severity = SEVERITY_MAP.get(vuln_name, "medium")
                            findings.append({
                                "id": f"FALLBACK-{vuln_id}",
                                "title": f"{vuln_name} pattern in {file.name}",
                                "severity": severity,
                                "cvss": {"critical":9.8,"high":8.0,"medium":6.5,"low":3.0}.get(severity,6.5),
                                "cvss_score": {"critical":9.8,"high":8.0,"medium":6.5,"low":3.0}.get(severity,6.5),
                                "category": vuln_name.lower().replace(" ","_"),
                                "asset_id": "web-01",
                                "file": str(file.relative_to(target_path)),
                                "pattern": pat,
                                "exploitability": 0.6 if severity=="critical" else 0.5,
                                "source": "fallback_static"
                            })
                            vuln_id += 1
                            break  # one per vuln type per file to avoid spam
                if len(findings) > 50:
                    break
        # If no findings, generate realistic mock from strix-like data
        if not findings:
            findings = self._mock_findings(target_path)
        return findings

    def _mock_findings(self, target_path: Path) -> List[Dict]:
        """Generate deterministic mock findings based on file count / name hash"""
        # Use target_path string hash to deterministically vary
        h = hash(str(target_path)) % 100
        base = [
            {"title":"SQL Injection in login endpoint","severity":"critical","cvss":9.8,"category":"sqli","asset_id":"web-01","exploitability":0.85},
            {"title":"Reflected XSS in search","severity":"high","cvss":7.5,"category":"xss","asset_id":"web-01","exploitability":0.7},
            {"title":"IDOR in /api/user/{id}","severity":"high","cvss":8.1,"category":"idor","asset_id":"api-01","exploitability":0.75},
            {"title":"Hardcoded AWS secret in config","severity":"medium","cvss":6.4,"category":"exposure","asset_id":"iam-01","exploitability":0.5},
            {"title":"SSRF in webhook handler","severity":"high","cvss":8.6,"category":"ssrf","asset_id":"api-01","exploitability":0.68},
            {"title":"Insecure deserialization in queue worker","severity":"critical","cvss":9.1,"category":"deserialization","asset_id":"api-01","exploitability":0.8},
        ]
        # Pick subset based on hash
        n = 3 + (h % 4)  # 3-6 findings
        findings = []
        for i in range(n):
            f = base[i % len(base)].copy()
            f["id"] = f"MOCK-{1000+i}"
            f["cvss_score"] = f["cvss"]
            f["source"] = "mock_strix"
            findings.append(f)
        return findings

    def try_real_strix(self, target_path: Path) -> Optional[List[Dict]]:
        """Attempt real strix scan if binary and docker available. Returns None if not possible."""
        strix_bin = shutil.which("strix")
        if not strix_bin:
            # Try pip's strix
            return None
        # Check docker
        try:
            r = subprocess.run(["docker","info"], capture_output=True, timeout=5)
            if r.returncode != 0:
                return None
        except:
            return None
        # Check LLM key
        if not os.getenv("LLM_API_KEY") and not os.getenv("NVIDIA_API_KEY"):
            return None
        # Try run strix non-interactive with json output
        # Strix writes to strix_runs/<name>
        run_name = f"upload-{uuid.uuid4().hex[:6]}"
        try:
            cmd = ["strix","-n","--target",str(target_path),"--run-name",run_name]
            env = os.environ.copy()
            # Pass NVIDIA as LLM if configured
            if os.getenv("NVIDIA_API_KEY") and not os.getenv("LLM_API_KEY"):
                env["LLM_API_KEY"] = os.getenv("NVIDIA_API_KEY")
                env["STRIX_LLM"] = os.getenv("NVIDIA_MODEL","meta/llama-3.1-70b-instruct")
            result = subprocess.run(cmd, capture_output=True, timeout=600, env=env, text=True)
            # Look for report
            report_candidates = list(Path("strix_runs").rglob("report.json")) + list(Path("strix_runs").rglob("findings.json"))
            for rep in report_candidates:
                if run_name in str(rep):
                    data = json.loads(rep.read_text())
                    # Normalize
                    if isinstance(data, dict) and "findings" in data:
                        return data["findings"]
                    if isinstance(data, list):
                        return data
            # Fallback parse stdout
            if result.stdout:
                # Try to find json in stdout
                m = re.search(r"\{.*\}|\[.*\]", result.stdout, re.DOTALL)
                if m:
                    try:
                        return json.loads(m.group(0))
                    except:
                        pass
            return None
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            return None

    def scan(self, upload_id: str) -> Dict[str, Any]:
        target = self.upload_dir / upload_id
        if not target.exists():
            return {"error": f"upload_id {upload_id} not found"}
        start = time.time()
        # Try real
        findings = self.try_real_strix(target)
        source = "strix"
        if findings is None:
            findings = self.fallback_static_scan(target)
            source = findings[0].get("source","fallback_static") if findings else "mock"
        elapsed = time.time() - start
        # Save report
        report_path = self.runs_dir / f"{upload_id}.json"
        report_path.write_text(json.dumps({"upload_id":upload_id,"source":source,"findings":findings}, indent=2))
        return {
            "upload_id": upload_id,
            "source": source,
            "findings": findings,
            "count": len(findings),
            "elapsed_sec": round(elapsed,2),
            "report_path": str(report_path)
        }

strix_integration = StrixIntegration()
