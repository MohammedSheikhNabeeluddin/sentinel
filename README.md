# AICTE Cyber Risk Quantification & Investment Optimization Platform + Strix

Cloud-ready cyber risk analytics that ingests security data (Strix pentest findings, vuln scanners, SIEM, IAM, EDR, CSPM, asset inventory, threat intel) and uses AI/ML (NVIDIA) to compute financial risk (EAL, VaR) + optimize investments.

**Location:** `D:\hackathon\cyber-risk-platform`  
**Strix:** `D:\hackathon\strix` (git clone) — used as pentest data source via `app/core/strix_integration.py`

## Quick Start
```powershell
cd D:\hackathon\cyber-risk-platform
# 1. set NVIDIA key only (endpoint pre-filled in .env)
notepad .env  # set NVIDIA_API_KEY=your_nvidia_key

# 2. install
pip install -r requirements.txt

# 3. run
python -m app.main
# or: uvicorn app.main:app --reload --port 8000

# open http://127.0.0.1:8000
```

## Features
- **Upload codebase** (.zip/.tar) → auto-extract → run Strix (`strix -n --target <uploads>`) or fallback static analysis → feed to risk engine
- **Risk Quantification Engine**: EAL = SLE × ARO, VaR, asset criticality, control effectiveness
- **AI Decision Support**: NVIDIA `meta/llama-3.1-70b-instruct` via `integrate.api.nvidia.com/v1` — NL query, predictive analytics, recommendations, what-if simulation
- **Investment Optimization**: 0/1 knapsack for max risk reduction per budget (₹1 crore default), ROSI = (ALE_before-ALE_after-cost)/cost, Investment vs Risk Reduction curve
- **Compliance Mapping**: ISO 27001, NIST CSF, CIS, RBI, SEBI
- **Dashboards**: Executive (Risk Score, Financial Exposure, Trend) + Technical (asset/control drill-down) + framework reports

## .env
`NVIDIA_ENDPOINT=https://integrate.api.nvidia.com/v1` pre-filled. Just add `NVIDIA_API_KEY`.

## API
- `POST /api/upload` — upload zip
- `POST /api/scan/{upload_id}` — trigger Strix
- `GET /api/risk/summary` — EAL/VaR
- `POST /api/query` — NL query (NVIDIA)
- `POST /api/simulate` — what-if
- `GET /api/investment/optimize?budget=10000000`
- `GET /api/compliance/{framework}`

See `app/` for modules.
